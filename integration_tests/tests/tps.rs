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

use anyhow::{Context as _, Result};
use bytesize::ByteSize;
use common::transaction::LeeTransaction;
use integration_tests::config::SequencerPartialConfig;
use lee::{
    Account, AccountId, PrivacyPreservingTransaction, PrivateKey, PublicKey, PublicTransaction,
    privacy_preserving_transaction::{self as pptx, circuit},
    program::Program,
    public_transaction as putx,
};
use lee_core::{
    AuthorizationSecretKey, DUMMY_COMMITMENT_HASH, InputAccountIdentity, MembershipProof,
    NullifierPublicKey, NullifierSecretKey, NullifierWitness, PrivateWitness, WitnessKind,
    account::{AccountWithMetadata, Nonce, data::Data},
    encryption::ViewingPublicKey,
};
use sequencer_core::config::GenesisAction;
use sequencer_service_rpc::RpcClient as _;
use test_fixtures::{
    MultiZoneTestContextBuilder, ZoneTestContextBuilder, config::MultiNodeTestContextConfig,
};
use tokio::test;
use wallet::DEFAULT_MAX_FEE;

/// Genesis supply per TPS account: enough to cover one transfer's fee reserve
/// (`gas_limit x base_fee` ≈ 0.8M at genesis fees) with ample headroom.
const TPS_ACCOUNT_SUPPLY: u128 = 10_000_000;

/// Declared execution gas per transfer. A metered native transfer runs
/// ~82k cycles; the declared limit gates how many transfers the builder packs
/// per block (`MAX_GAS_EXEC` over the limit), so it is kept tight — at 100k the block
/// carries ~100 transfers, which is what makes the 8 TPS target reachable.
const TPS_TRANSFER_GAS_LIMIT: u64 = 100_000;

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

    /// Claim funds from each account's vault PDA into the account itself.
    ///
    /// `GenesisAction::SupplyAccount` funds vault PDAs (not accounts directly), so this step is
    /// required before sending `authenticated_transfer` transactions from these accounts.
    /// All claim transactions are submitted at once and then confirmed sequentially.
    /// After this call every account has nonce 1, so `build_public_txs` must be called after it.
    pub async fn claim_vault_funds(
        &self,
        sequencer_client: &sequencer_service_rpc::SequencerClient,
    ) -> Result<()> {
        let vault_program_id = programs::vault().id();

        let mut tx_hashes = Vec::with_capacity(self.public_keypairs.len());
        for (private_key, account_id) in &self.public_keypairs {
            let owner_vault_id =
                vault_core::compute_vault_account_id(vault_program_id, *account_id);
            // A claim of the vault's entire balance is a fee-exempt full
            // sweep, so the not-yet-funded accounts can afford it.
            let message = putx::Message::try_new(
                vault_program_id,
                vec![*account_id, owner_vault_id],
                vec![Nonce(0_u128)],
                vault_core::Instruction::Claim {
                    amount: TPS_ACCOUNT_SUPPLY,
                },
            )
            .context("Failed to build vault claim message")?;
            let witness_set =
                lee::public_transaction::WitnessSet::for_message(&message, &[private_key]);
            let tx = PublicTransaction::new(message, witness_set);
            let hash = sequencer_client
                .send_transaction(LeeTransaction::Public(tx))
                .await
                .context("Failed to submit vault claim")?;
            tx_hashes.push(hash);
        }

        let deadline = Instant::now() + Duration::from_mins(5);
        for (i, tx_hash) in tx_hashes.iter().enumerate() {
            loop {
                anyhow::ensure!(
                    Instant::now() < deadline,
                    "Vault claims timed out after 5 minutes ({i}/{} confirmed)",
                    tx_hashes.len()
                );
                let found = sequencer_client
                    .get_transaction(*tx_hash)
                    .await
                    .ok()
                    .flatten()
                    .is_some();
                if found {
                    break;
                }
            }
        }
        Ok(())
    }

    /// Build a batch of public transactions to submit to the node.
    ///
    /// Must be called after `claim_vault_funds`, which sets each account's nonce to 1.
    pub fn build_public_txs(&self) -> Vec<PublicTransaction> {
        // Create valid public transactions
        let program = programs::authenticated_transfer();
        let public_txs: Vec<PublicTransaction> = self
            .public_keypairs
            .windows(2)
            .map(|pair| {
                let amount: u128 = 1;
                let message = putx::Message::try_new_with_fees(
                    program.id(),
                    [pair[0].1, pair[1].1].to_vec(),
                    [Nonce(1_u128)].to_vec(),
                    authenticated_transfer_core::Instruction::Transfer { amount },
                    // A generous max_fee (a ceiling, not the fee paid) so the
                    // base-fee rise this test's own sustained load causes cannot
                    // push the reserve past it and drop later txs.
                    lee::FeeDeclaration::new(pair[0].1, TPS_TRANSFER_GAS_LIMIT, 0, DEFAULT_MAX_FEE),
                )
                .unwrap();
                let witness_set =
                    lee::public_transaction::WitnessSet::for_message(&message, &[&pair[0].0]);
                PublicTransaction::new(message, witness_set)
            })
            .collect();

        public_txs
    }

    /// Generates a sequencer configuration with initial balance in a number of public accounts.
    /// The transactions generated with the function `build_public_txs` will be valid in a node
    /// started with the config from this method.
    fn generate_genesis(&self) -> Vec<GenesisAction> {
        self.public_keypairs
            .iter()
            .map(|(_, account_id)| GenesisAction::SupplyAccount {
                account_id: *account_id,
                balance: TPS_ACCOUNT_SUPPLY,
            })
            .collect()
    }

    const fn generate_sequencer_partial_config() -> SequencerPartialConfig {
        SequencerPartialConfig {
            max_num_tx_in_block: 300,
            // The largest block Bedrock can carry as one inscription.
            max_block_size: ByteSize::b(sequencer_core::config::MAX_PUBLISHABLE_BLOCK_SIZE),
            mempool_max_size: 10_000,
            block_create_timeout: Duration::from_secs(12),
            priority_fee_percent: sequencer_core::config::default_priority_fee_percent(),
        }
    }
}

// TODO: Make a proper benchmark instead of an ad-hoc test
#[test]
pub async fn tps_test() -> Result<()> {
    let num_transactions = 300 * 5;
    let target_tps = 8;

    let tps_test = TpsTestManager::new(target_tps, num_transactions);

    let ctx = MultiZoneTestContextBuilder::default()
        .with_zone(
            ZoneTestContextBuilder::new(MultiNodeTestContextConfig::default())
                .with_sequencer_partial_config(TpsTestManager::generate_sequencer_partial_config())
                .with_genesis(tps_test.generate_genesis()),
        )
        .build()
        .await?;

    // Genesis funds vault PDAs, not accounts directly. Claim into accounts before measuring.
    tps_test
        .claim_vault_funds(ctx.sequencer_client())
        .await
        .context("Failed to claim vault funds for TPS accounts")?;

    let target_time = tps_test.target_time();
    log::info!(
        "TPS test begin. Target time is {target_time:?} for {num_transactions} transactions ({target_tps} TPS)"
    );

    let txs = tps_test.build_public_txs();
    let now = Instant::now();

    let mut tx_hashes = vec![];
    for (i, tx) in txs.into_iter().enumerate() {
        let tx_hash = ctx
            .sequencer_client()
            .send_transaction(LeeTransaction::Public(tx))
            .await
            .unwrap();
        log::info!("Sent tx {i}");
        tx_hashes.push(tx_hash);
    }

    for (i, tx_hash) in tx_hashes.iter().enumerate() {
        loop {
            assert!(
                now.elapsed().as_millis() <= target_time.as_millis(),
                "TPS test failed by timeout, transactions processed {i}/{num_transactions}"
            );

            let tx_obj = ctx
                .sequencer_client()
                .get_transaction(*tx_hash)
                .await
                .inspect_err(|err| {
                    log::warn!("Failed to get transaction by hash {tx_hash} with error: {err:#?}");
                });

            if tx_obj.is_ok_and(|opt| opt.is_some()) {
                log::info!("Found tx {i} with hash {tx_hash}");
                break;
            }
        }
    }
    let time_elapsed = now.elapsed().as_secs();

    let tx_processed = tx_hashes.len();
    let actual_tps = tx_processed as u64 / time_elapsed;
    log::info!("Processed {tx_processed} transactions in {time_elapsed:?} ({actual_tps} TPS)",);

    assert_eq!(tx_processed, num_transactions);

    assert!(
        time_elapsed <= target_time.as_secs(),
        "Elapsed time {time_elapsed:?} exceeded target time {target_time:?}"
    );

    // Guard against silent revert-keeps-fee false passes: an OutOfGas-reverted
    // transfer is still INCLUDED (fee charged, nonce burned), so `get_transaction`
    // returning does not prove the transfer executed. The last keypair is a pure
    // recipient in the chained transfers (never a sender, so never charged a fee),
    // making its post-state deterministic: it must have gained exactly the
    // transferred amount (1) over its genesis supply. If the chain reverted instead
    // of executing, it would still sit at its untouched genesis supply.
    let last_recipient = tps_test.public_keypairs.last().unwrap().1;
    let last_recipient_balance = ctx
        .sequencer_client()
        .get_account_balance(last_recipient)
        .await
        .context("Failed to fetch last recipient balance")?;
    assert_eq!(
        last_recipient_balance,
        TPS_ACCOUNT_SUPPLY + 1,
        "Last recipient balance mismatch: transfers were included but did not execute \
         (revert-keeps-fee), so no funds actually moved"
    );

    log::info!("TPS test finished successfully");

    Ok(())
}

/// Builds a single privacy transaction to use in stress tests. This involves generating a proof so
/// it may take a while to run. In normal execution of the node this transaction will be accepted
/// only once. Disabling the node's nullifier uniqueness check allows to submit this transaction
/// multiple times with the purpose of testing the node's processing performance.
#[expect(dead_code, reason = "No idea if we need this, should we remove it?")]
fn build_privacy_transaction() -> PrivacyPreservingTransaction {
    let program = programs::authenticated_transfer();
    let sender_ask = AuthorizationSecretKey([1; 32]);
    let sender_nsk = NullifierSecretKey::from(&sender_ask);
    let sender_vpk = ViewingPublicKey::from_seed(&[99_u8; 32], &[100_u8; 32]);
    let sender_npk = NullifierPublicKey::from(&sender_nsk);
    let sender_pre = AccountWithMetadata::new(
        Account {
            balance: 100,
            nonce: Nonce(0xdead_beef),
            program_owner: program.id().into(),
            data: Data::default(),
        },
        true,
        AccountId::for_regular_private_account(&sender_npk, &sender_vpk, 0),
    );
    let recipient_ask = AuthorizationSecretKey([2; 32]);
    let recipient_nsk = NullifierSecretKey::from(&recipient_ask);
    let recipient_vpk = ViewingPublicKey::from_seed(&[101_u8; 32], &[102_u8; 32]);
    let recipient_npk = NullifierPublicKey::from(&recipient_nsk);
    let recipient_pre = AccountWithMetadata::new(
        Account::default(),
        true,
        AccountId::for_regular_private_account(&recipient_npk, &recipient_vpk, 0),
    );

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
        Program::serialize_instruction(authenticated_transfer_core::Instruction::Transfer {
            amount: balance_to_move,
        })
        .unwrap(),
        vec![
            InputAccountIdentity::Private(PrivateWitness {
                vpk: sender_vpk,
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular {
                    ask: Some(sender_ask),
                },
                nullifier: NullifierWitness::Update {
                    view_tag: 0,
                    nsk: sender_nsk,
                    membership_proof: proof,
                },
            }),
            InputAccountIdentity::Private(PrivateWitness {
                vpk: recipient_vpk,
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular {
                    ask: Some(recipient_ask),
                },
                nullifier: NullifierWitness::Init {
                    npk: recipient_npk,
                    commitment_root: DUMMY_COMMITMENT_HASH,
                },
            }),
        ],
        &program.into(),
    )
    .unwrap();
    let message = pptx::message::Message::from_circuit_output(vec![], output);
    let witness_set = pptx::witness_set::WitnessSet::for_message(&message, proof, &[]);
    pptx::PrivacyPreservingTransaction::new(message, witness_set)
}
