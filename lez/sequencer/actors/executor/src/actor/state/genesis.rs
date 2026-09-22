// TODO: Consider making a separate crate out of this module and genesis-related parts of
// sequencer_core.

use common::{
    HashType,
    block::{Block, HashableBlockData},
    transaction::LeeTransaction,
};
use lee::{AccountId, GENESIS_BLOCK_ID, PublicTransaction};
use sequencer_core::{
    Ed25519PublicKey,
    config::{GenesisAction, SequencerConfig},
};

/// A founding sequencer's key, plus the ownership account attesting to its stake.
struct FoundingStake {
    /// Index of the `StakeSequencer` action configuring this stake, which names
    /// the genesis deposit funding it.
    genesis_index: u64,
    key: sequencer_stake_core::SequencerKey,
    owner: lee::PublicKey,
    signature: lee::Signature,
}

/// The pre-genesis state: `testnet_initial_state`, nothing else. Everything is
/// applied as genesis transactions in [`build_genesis_state`] so followers replay it.
pub fn build_initial_state(config: &SequencerConfig) -> lee::V03State {
    let cross_zone = config.cross_zone.is_some();
    let base = testnet_initial_state::initial_state(cross_zone);

    // Stamped on fresh genesis and restore-replay: compare against the
    // indexer's on divergence.
    log::info!(
        "Genesis fingerprint: {}",
        hex::encode(base.genesis_fingerprint())
    );
    base
}

/// The genesis block and state `config` describes.
pub fn genesis_block_and_state(
    signing_key: &lee::PrivateKey,
    bootstrap_sequencer_key: Option<sequencer_stake_core::SequencerKey>,
    config: &SequencerConfig,
) -> (Block, lee::V03State) {
    let (genesis_state, genesis_txs) =
        build_genesis_state(signing_key, config, bootstrap_sequencer_key);
    let genesis_block = HashableBlockData {
        block_id: lee::GENESIS_BLOCK_ID,
        transactions: genesis_txs,
        prev_block_hash: HashType([0; 32]),
        timestamp: 0,
    }
    .into_pending_block(signing_key);

    (genesis_block, genesis_state)
}

/// Builds the initial genesis state from [`build_initial_state`] plus configured
/// genesis transactions. Returns the final state and the list of
/// [`LeeTransaction`]s that should be committed to the genesis block so external
/// observers can replay them.
fn build_genesis_state(
    signing_key: &lee::PrivateKey,
    config: &SequencerConfig,
    bootstrap_sequencer_key: Option<sequencer_stake_core::SequencerKey>,
) -> (lee::V03State, Vec<LeeTransaction>) {
    let mut state = build_initial_state(config);

    // Config txs seed the config accounts by transaction, so every node
    // reconstructs them by replaying the genesis block. Every cross-zone config
    // is initialized: each builtin has a user-callable InitConfig, so a default
    // config PDA would be claimable by the first initializer. The inbox's is
    // receiving-zones-only.
    // The self-stake is appended here, so every index below is an index into
    // this list, not into `config.genesis`.
    let genesis_actions = effective_genesis_actions(config, bootstrap_sequencer_key);

    let cross_zone_declared = config.cross_zone.as_ref();
    assert!(
        cross_zone_declared.is_some() || bridge_lock_holdings(&genesis_actions).next().is_none(),
        "SupplyBridgeLockHolding requires cross_zone to be configured: bridge_lock is not registered on this zone"
    );
    let cross_zone_config_txs = cross_zone_declared
        .map(|cross_zone| {
            [
                cross_zone::build_wrapped_token_init_config_tx(cross_zone),
                cross_zone::build_ping_sender_init_config_tx(),
                cross_zone::build_ping_receiver_init_config_tx(cross_zone),
                cross_zone::build_bridge_lock_init_config_tx(),
            ]
        })
        .into_iter()
        .flatten();
    let inbox_config_tx = cross_zone_declared.map(|_| {
        let self_zone = *config.bedrock_config.channel_id.as_ref();
        cross_zone::build_inbox_init_config_tx(self_zone)
    });
    let supply_txs = genesis_actions
        .iter()
        .enumerate()
        .filter_map(|(index, action)| {
            let index = u64::try_from(index).expect("genesis action count fits in u64");
            match action {
                GenesisAction::SupplyAccount {
                    account_id,
                    balance,
                } => Some(build_supply_account_genesis_transaction(
                    account_id,
                    *balance,
                    genesis_deposit_op_id(index),
                )),
                GenesisAction::SupplyBridgeLockHolding { holder, amount } => {
                    Some(build_supply_account_genesis_transaction(
                        &cross_zone::bridge_lock_holding_account_id(*holder),
                        *amount,
                        genesis_deposit_op_id(index),
                    ))
                }
                // Stakes are built below.
                GenesisAction::StakeSequencer { .. } => None,
            }
        });

    let staked = founding_stakes(&genesis_actions);
    let bootstrap_stake_txs = build_stake_genesis_transactions(
        &staked,
        config.bedrock_config.channel_params.minimum_sequencer_stake,
    );

    let mut genesis_txs: Vec<_> = std::iter::once(build_init_channel_params_transaction(
        config.bedrock_config.channel_params,
        *config.bedrock_config.channel_id.as_ref(),
    ))
    .chain(cross_zone_config_txs)
    .chain(inbox_config_tx)
    .chain(supply_txs)
    .chain(bootstrap_stake_txs)
    .inspect(|tx| {
        state
            .transition_from_public_transaction(tx, GENESIS_BLOCK_ID, 0)
            .expect("Failed to execute genesis transaction");
    })
    .collect();

    // The genesis fee tx credits the first staked sequencer's ownership
    // account, already claimed by its stake tx above (which ran earlier in this
    // same genesis block), so no separate initialization is needed.
    //
    // A stakeless genesis (e.g. a sequencer reconstructing an existing channel
    // it did not bootstrap) has no staked account to reward, so it falls back to
    // the signing key's account: this genesis is a throwaway placeholder (the real
    // one is replayed from the channel), the summary is the default, so the
    // credit is zero and the unclaimed account is left untouched.
    let producer = staked.first().map_or_else(
        || lee::AccountId::from(&lee::PublicKey::new_from_private_key(signing_key)),
        |stake| lee::AccountId::from(&stake.owner),
    );
    for tx in [
        common::transaction::fee_invocation(fee_core::BlockFeeSummary::default(), producer),
        common::transaction::clock_invocation(0),
    ] {
        state
            .transition_from_public_transaction(&tx, GENESIS_BLOCK_ID, 0)
            .expect("Failed to execute genesis transaction");
        genesis_txs.push(tx);
    }
    let genesis_txs = genesis_txs
        .into_iter()
        .map(LeeTransaction::Public)
        .collect();

    (state, genesis_txs)
}

/// `config.genesis`, plus the creator's self-stake when nothing configures one.
///
/// A self-stake is authored at startup rather than by hand, so appending it as
/// a real action lets the rest of genesis treat it like any other: one staker
/// and many are the same path, differing only in count.
fn effective_genesis_actions(
    config: &SequencerConfig,
    bootstrap_sequencer_key: Option<sequencer_stake_core::SequencerKey>,
) -> Vec<GenesisAction> {
    let mut actions = config.genesis.clone();
    if actions
        .iter()
        .any(|action| matches!(action, GenesisAction::StakeSequencer { .. }))
    {
        return actions;
    }

    actions.extend(bootstrap_sequencer_key.map(|key| {
        let key_path = config.home.join("sequencer_stake_signing_key");
        let owner = sequencer_core::load_or_create_stake_signing_key(&key_path)
            .expect("Failed to load or create the stake signing key");
        GenesisAction::StakeSequencer {
            sequencer_key: key,
            ownership_public_key: lee::PublicKey::new_from_private_key(&owner),
            // The only stake, so it is the first to sign with the funding key.
            stake_signature: sequencer_core::sign_genesis_stake(
                0,
                key,
                &owner,
                config.bedrock_config.channel_params.minimum_sequencer_stake,
            ),
        }
    }));
    actions
}

/// Bridge-lock holder balances configured for this zone's genesis.
fn bridge_lock_holdings(
    genesis: &[GenesisAction],
) -> impl Iterator<Item = (lee::AccountId, u64)> + '_ {
    genesis.iter().filter_map(|action| match action {
        GenesisAction::SupplyBridgeLockHolding { holder, amount } => Some((*holder, *amount)),
        GenesisAction::SupplyAccount { .. } | GenesisAction::StakeSequencer { .. } => None,
    })
}

/// The founding sequencers' `Stake`s, funded by a genesis deposit. Real
/// transactions, not raw state, so followers replay them instead of missing them.
fn build_stake_genesis_transactions(
    staked: &[FoundingStake],
    minimum_stake: u128,
) -> Vec<PublicTransaction> {
    if staked.is_empty() {
        return Vec::new();
    }

    let funding_key = lee::PrivateKey::try_new(sequencer_core::GENESIS_STAKE_FUNDING_KEY).unwrap();
    let funding_public_key = lee::PublicKey::new_from_private_key(&funding_key);
    let amount = u64::try_from(minimum_stake).expect("minimum sequencer stake exceeds u64");

    // One deposit per stake, so no total has to fit `u64`. They precede the
    // stakes because each one funds the account the stakes draw on.
    let mut txs: Vec<_> = staked
        .iter()
        .map(|stake| {
            build_supply_account_genesis_transaction(
                &sequencer_core::genesis_stake_funding_account(),
                amount,
                genesis_deposit_op_id(stake.genesis_index),
            )
        })
        .collect();

    for (index, stake) in staked.iter().enumerate() {
        let ownership_id = AccountId::from(&stake.owner);
        let stake_message =
            sequencer_core::genesis_stake_message(index, stake.key, ownership_id, minimum_stake);
        let stake_witness_set = lee::public_transaction::WitnessSet::from_raw_parts(vec![
            (
                lee::Signature::new(&funding_key, &stake_message.hash()),
                funding_public_key.clone(),
            ),
            (stake.signature.clone(), stake.owner.clone()),
        ]);

        // Redundant with the signature check every tx gets, but names the entry.
        assert!(
            stake_witness_set.is_valid_for(&stake_message),
            "genesis stake signature does not match founding sequencer {index} ({})",
            hex::encode(stake.key)
        );

        txs.push(PublicTransaction::new(stake_message, stake_witness_set));
    }

    txs
}

/// Op id of the `index`-th genesis allocation.
///
/// Genesis allocations are `Deposit`s with no L1 event behind them, so their op
/// ids must be unmistakable: an L1 op id is a hash, and this is a literal ASCII
/// domain followed by the index, which no hash realistically produces. The
/// receipt PDA each one claims is what stops a later block replaying it.
fn genesis_deposit_op_id(index: u64) -> [u8; 32] {
    const DOMAIN: &[u8; 24] = b"/LEZ/v0.3/GenesisDeposit";

    let mut op_id = [0_u8; 32];
    op_id[..DOMAIN.len()].copy_from_slice(DOMAIN);
    op_id[DOMAIN.len()..].copy_from_slice(&index.to_le_bytes());
    op_id
}

fn build_supply_account_genesis_transaction(
    account_id: &AccountId,
    amount: u64,
    op_id: [u8; 32],
) -> PublicTransaction {
    let bridge_program_id: AccountId = programs::bridge().id().into();
    let receipt_id = bridge_core::deposit_receipt_account_id(bridge_program_id, op_id);

    let message = lee::public_transaction::Message::try_new(
        bridge_program_id,
        vec![
            system_accounts::bridge_account_id(),
            *account_id,
            receipt_id,
        ],
        Vec::new(),
        bridge_core::Instruction::Deposit {
            l1_deposit_op_id: op_id,
            recipient_id: *account_id,
            amount,
        },
    )
    .expect("Failed to serialize genesis deposit instruction");
    let witness_set = lee::public_transaction::WitnessSet::from_raw_parts(Vec::new());

    PublicTransaction::new(message, witness_set)
}

/// Sets the channel posting params in the `sequencer_stake` config account.
/// Unsigned and replayable, so an indexer reconstructs it from the genesis
/// block rather than needing the sequencer's config.
fn build_init_channel_params_transaction(
    channel_params: sequencer_stake_core::ChannelParams,
    channel_id: [u8; 32],
) -> PublicTransaction {
    let message = lee::public_transaction::Message::try_new(
        programs::sequencer_stake().id().into(),
        vec![system_accounts::sequencer_stake_config_account_id()],
        vec![],
        sequencer_stake_core::Instruction::InitChannelParams {
            params: channel_params,
            channel_id,
        },
    )
    .expect("Failed to build the InitChannelParams genesis message");
    PublicTransaction::new(
        message,
        lee::public_transaction::WitnessSet::from_raw_parts(vec![]),
    )
}

fn founding_stakes(genesis: &[GenesisAction]) -> Vec<FoundingStake> {
    genesis
        .iter()
        .enumerate()
        .filter_map(|(index, action)| match action {
            GenesisAction::StakeSequencer {
                sequencer_key,
                ownership_public_key,
                stake_signature,
            } => {
                let index = u64::try_from(index).expect("genesis action count fits in u64");
                Some(FoundingStake {
                    genesis_index: index,
                    key: *sequencer_key,
                    owner: ownership_public_key.clone(),
                    signature: stake_signature.clone(),
                })
            }
            GenesisAction::SupplyAccount { .. } | GenesisAction::SupplyBridgeLockHolding { .. } => {
                None
            }
        })
        .collect()
}

/// The accredited keys a newly created channel should carry, `own_key` first
/// because creation gives the turn to index 0. `None` leaves creation to the
/// plain inscription path.
pub fn founding_committee(
    config: &SequencerConfig,
    own_key: sequencer_stake_core::SequencerKey,
) -> Option<Vec<Ed25519PublicKey>> {
    let mut keys: Vec<_> = founding_stakes(&config.genesis)
        .into_iter()
        .map(|stake| stake.key)
        .collect();
    if keys.is_empty() {
        return None;
    }
    keys.sort_unstable();
    keys.retain(|key| *key != own_key);

    Some(
        std::iter::once(own_key)
            .chain(keys)
            .map(|key| {
                Ed25519PublicKey::from_bytes(&key.to_bytes())
                    .expect("sequencer key was decoded from a valid Ed25519 public key")
            })
            .collect(),
    )
}
