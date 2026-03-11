#![expect(
    clippy::arithmetic_side_effects,
    clippy::float_arithmetic,
    clippy::missing_asserts_for_indexing,
    clippy::as_conversions,
    clippy::tests_outside_test_module,
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "We don't care about these in tests"
)]

use std::time::{Duration, Instant};

use anyhow::Result;
use bytesize::ByteSize;
use integration_tests::{
    TestContext,
    config::{InitialData, SequencerPartialConfig},
};
use key_protocol::key_management::{KeyChain, ephemeral_key_holder::EphemeralKeyHolder};
use log::info;
use nssa::{
    Account, AccountId, PrivacyPreservingTransaction, PrivateKey, PublicKey, PublicTransaction,
    privacy_preserving_transaction::{self as pptx, circuit},
    program::Program,
    public_transaction as putx,
};
use nssa_core::{
    MembershipProof, NullifierPublicKey,
    account::{AccountWithMetadata, data::Data},
    encryption::ViewingPublicKey,
};
use tokio::test;

pub(crate) struct TpsTestManager {
    public_keypairs: Vec<(PrivateKey, AccountId)>,
    target_tps: u64,
}

impl TpsTestManager {
    /// Generates public account keypairs. These are used to populate the config and to generate
    /// valid public transactions for the tps test.
    pub(crate) fn new(target_tps: u64, number_transactions: usize) -> Self {
        let public_keypairs = (1..(number_transactions + 2))
            .map(|i| {
                let mut private_key_bytes = [0_u8; 32];
                private_key_bytes[..8].copy_from_slice(&i.to_le_bytes());
                let private_key = PrivateKey::try_new(private_key_bytes).unwrap();
                let public_key = PublicKey::new_from_private_key(&private_key);
                let account_id = AccountId::from(&public_key);
                (private_key, account_id)
            })
            .collect();
        Self {
            public_keypairs,
            target_tps,
        }
    }

    #[expect(
        clippy::cast_precision_loss,
        reason = "This is just for testing purposes, we don't care about precision loss here"
    )]
    pub(crate) fn target_time(&self) -> Duration {
        let number_transactions = (self.public_keypairs.len() - 1) as u64;
        Duration::from_secs_f64(number_transactions as f64 / self.target_tps as f64)
    }

    /// Build a batch of public transactions to submit to the node.
    pub fn build_public_txs(&self) -> Vec<PublicTransaction> {
        // Create valid public transactions
        let program = Program::authenticated_transfer_program();
        let public_txs: Vec<PublicTransaction> = self
            .public_keypairs
            .windows(2)
            .map(|pair| {
                let amount: u128 = 1;
                let message = putx::Message::try_new(
                    program.id(),
                    [pair[0].1, pair[1].1].to_vec(),
                    [0_u128].to_vec(),
                    amount,
                )
                .unwrap();
                let witness_set =
                    nssa::public_transaction::WitnessSet::for_message(&message, &[&pair[0].0]);
                PublicTransaction::new(message, witness_set)
            })
            .collect();

        public_txs
    }

    /// Generates a sequencer configuration with initial balance in a number of public accounts.
    /// The transactions generated with the function `build_public_txs` will be valid in a node
    /// started with the config from this method.
    fn generate_initial_data(&self) -> InitialData {
        // Create public public keypairs
        let public_accounts = self
            .public_keypairs
            .iter()
            .map(|(key, _)| (key.clone(), 10))
            .collect();

        // Generate an initial commitment to be used with the privacy preserving transaction
        // created with the `build_privacy_transaction` function.
        let key_chain = KeyChain::new_os_random();
        let account = Account {
            balance: 100,
            nonce: 0xdead_beef,
            program_owner: Program::authenticated_transfer_program().id(),
            data: Data::default(),
        };

        InitialData {
            public_accounts,
            private_accounts: vec![(key_chain, account)],
        }
    }

    const fn generate_sequencer_partial_config() -> SequencerPartialConfig {
        SequencerPartialConfig {
            max_num_tx_in_block: 300,
            max_block_size: ByteSize::mb(500),
            mempool_max_size: 10_000,
            block_create_timeout: Duration::from_secs(12),
        }
    }
}

// TODO: Make a proper benchmark instead of an ad-hoc test
#[test]
pub async fn tps_test() -> Result<()> {
    let num_transactions = 300 * 5;
    let target_tps = 8;

    let tps_test = TpsTestManager::new(target_tps, num_transactions);
    let ctx = TestContext::builder()
        .with_sequencer_partial_config(TpsTestManager::generate_sequencer_partial_config())
        .with_initial_data(tps_test.generate_initial_data())
        .build()
        .await?;

    let target_time = tps_test.target_time();
    info!(
        "TPS test begin. Target time is {target_time:?} for {num_transactions} transactions ({target_tps} TPS)"
    );

    let txs = tps_test.build_public_txs();
    let now = Instant::now();

    let mut tx_hashes = vec![];
    for (i, tx) in txs.into_iter().enumerate() {
        let tx_hash = ctx
            .sequencer_client()
            .send_tx_public(tx)
            .await
            .unwrap()
            .tx_hash;
        info!("Sent tx {i}");
        tx_hashes.push(tx_hash);
    }

    for (i, tx_hash) in tx_hashes.iter().enumerate() {
        loop {
            assert!(
                now.elapsed().as_millis() <= target_time.as_millis(),
                "TPS test failed by timeout"
            );

            let tx_obj = ctx
                .sequencer_client()
                .get_transaction_by_hash(*tx_hash)
                .await
                .inspect_err(|err| {
                    log::warn!("Failed to get transaction by hash {tx_hash} with error: {err:#?}");
                });

            if let Ok(tx_obj) = tx_obj
                && tx_obj.transaction.is_some()
            {
                info!("Found tx {i} with hash {tx_hash}");
                break;
            }
        }
    }
    let time_elapsed = now.elapsed().as_secs();

    let tx_processed = tx_hashes.len();
    let actual_tps = tx_processed as u64 / time_elapsed;
    info!("Processed {tx_processed} transactions in {time_elapsed:?} ({actual_tps} TPS)",);

    assert_eq!(tx_processed, num_transactions);

    assert!(
        time_elapsed <= target_time.as_secs(),
        "Elapsed time {time_elapsed:?} exceeded target time {target_time:?}"
    );

    info!("TPS test finished successfully");

    Ok(())
}

/// Builds a single privacy transaction to use in stress tests. This involves generating a proof so
/// it may take a while to run. In normal execution of the node this transaction will be accepted
/// only once. Disabling the node's nullifier uniqueness check allows to submit this transaction
/// multiple times with the purpose of testing the node's processing performance.
#[expect(dead_code, reason = "No idea if we need this, should we remove it?")]
fn build_privacy_transaction() -> PrivacyPreservingTransaction {
    let program = Program::authenticated_transfer_program();
    let sender_nsk = [1; 32];
    let sender_vsk = [99; 32];
    let sender_vpk = ViewingPublicKey::from_scalar(sender_vsk);
    let sender_npk = NullifierPublicKey::from(&sender_nsk);
    let sender_pre = AccountWithMetadata::new(
        Account {
            balance: 100,
            nonce: 0xdead_beef,
            program_owner: program.id(),
            data: Data::default(),
        },
        true,
        AccountId::from(&sender_npk),
    );
    let recipient_nsk = [2; 32];
    let recipient_vsk = [99; 32];
    let recipient_vpk = ViewingPublicKey::from_scalar(recipient_vsk);
    let recipient_npk = NullifierPublicKey::from(&recipient_nsk);
    let recipient_pre =
        AccountWithMetadata::new(Account::default(), false, AccountId::from(&recipient_npk));

    let eph_holder_from = EphemeralKeyHolder::new(&sender_npk);
    let sender_ss = eph_holder_from.calculate_shared_secret_sender(&sender_vpk);
    let sender_epk = eph_holder_from.generate_ephemeral_public_key();

    let eph_holder_to = EphemeralKeyHolder::new(&recipient_npk);
    let recipient_ss = eph_holder_to.calculate_shared_secret_sender(&recipient_vpk);
    let recipient_epk = eph_holder_from.generate_ephemeral_public_key();

    let balance_to_move: u128 = 1;
    let proof: MembershipProof = (
        1,
        vec![[
            170, 10, 217, 228, 20, 35, 189, 177, 238, 235, 97, 129, 132, 89, 96, 247, 86, 91, 222,
            214, 38, 194, 216, 67, 56, 251, 208, 226, 0, 117, 149, 39,
        ]],
    );
    let (output, proof) = circuit::execute_and_prove(
        vec![sender_pre, recipient_pre],
        Program::serialize_instruction(balance_to_move).unwrap(),
        vec![1, 2],
        vec![0xdead_beef1, 0xdead_beef2],
        vec![
            (sender_npk.clone(), sender_ss),
            (recipient_npk.clone(), recipient_ss),
        ],
        vec![sender_nsk],
        vec![Some(proof)],
        &program.into(),
    )
    .unwrap();
    let message = pptx::message::Message::try_from_circuit_output(
        vec![],
        vec![],
        vec![
            (sender_npk, sender_vpk, sender_epk),
            (recipient_npk, recipient_vpk, recipient_epk),
        ],
        output,
    )
    .unwrap();
    let witness_set = pptx::witness_set::WitnessSet::for_message(&message, proof, &[]);
    pptx::PrivacyPreservingTransaction::new(message, witness_set)
}
