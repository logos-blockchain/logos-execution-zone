//! Genesis of a sequencer chain: the pre-genesis state and the genesis block every node replays.

use common::{
    HashType,
    block::{Block, HashableBlockData},
    transaction::LeeTransaction,
};
pub use cross_zone_inbox_core::CrossZoneConfig;
use lee::{AccountId, GENESIS_BLOCK_ID, PublicKey, PublicTransaction, Signature};
use lee_core::account::Nonce;
use sequencer_stake_core::{ChannelParams, SequencerKey};
use serde::{Deserialize, Serialize};

/// Fixed, public key behind a genesis-only funding account.
///
/// The bridge can only be called top-level, not as `Stake`'s mover, so this
/// account is a pass-through that receives the genesis deposit and then moves
/// it into the real stake account. Not a secret: every node derives the same
/// account, and it holds nothing once genesis has run.
// TODO: replace the pass-through with a real Bedrock deposit, once that path
// exists. The genesis deposit funding it is synthetic, so this stays a fixed
// genesis-only key rather than a founding sequencer staking bridged funds.
pub const GENESIS_STAKE_FUNDING_KEY: [u8; 32] = [9; 32];

/// A transaction to be applied at genesis to supply initial balances.
///
/// Amounts are `u64`, not [`lee::Balance`], because every one is funded through
/// the bridge's `Deposit`, whose amount is `u64`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GenesisAction {
    SupplyAccount {
        account_id: AccountId,
        balance: u64,
    },
    /// Funds a holder's holding PDA at genesis with one replayable genesis
    /// credit; the balance-only PDA needs no claim.
    SupplyBridgeLockHolding {
        holder: AccountId,
        amount: u64,
    },
    /// Stakes `sequencer_key` at genesis.
    StakeSequencer {
        sequencer_key: SequencerKey,
        ownership_public_key: PublicKey,
        stake_signature: Signature,
    },
}

/// Everything a chain's genesis is built from.
#[derive(Clone, Debug)]
pub struct GenesisConfig {
    pub channel_id: [u8; 32],
    pub channel_params: ChannelParams,
    /// Presence selects the genesis program set.
    pub cross_zone: Option<CrossZoneConfig>,
    /// Applied in order, founding stakes included.
    pub actions: Vec<GenesisAction>,
}

/// A founding sequencer's key, plus the ownership account attesting to its stake.
struct FoundingStake {
    /// Index of the `StakeSequencer` action configuring this stake, which names
    /// the genesis deposit funding it.
    genesis_index: u64,
    key: SequencerKey,
    owner: PublicKey,
    signature: Signature,
}

/// The pre-genesis state: `testnet_initial_state`, nothing else. Everything is
/// applied as genesis transactions in [`build_genesis_state`] so followers replay it.
#[must_use]
pub fn build_initial_state(cross_zone: bool) -> lee::V03State {
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
#[must_use]
pub fn genesis_block_and_state(
    signing_key: &lee::PrivateKey,
    config: &GenesisConfig,
) -> (Block, lee::V03State) {
    let (genesis_state, genesis_txs) = build_genesis_state(signing_key, config);
    let genesis_block = HashableBlockData {
        block_id: GENESIS_BLOCK_ID,
        transactions: genesis_txs,
        prev_block_hash: HashType([0; 32]),
        timestamp: 0,
    }
    .into_pending_block(signing_key);

    (genesis_block, genesis_state)
}

/// Builds the initial genesis state from [`build_initial_state`] plus the
/// configured genesis transactions.
///
/// Returns the final state and the list of [`LeeTransaction`]s that should be
/// committed to the genesis block so external observers can replay them.
#[must_use]
pub fn build_genesis_state(
    signing_key: &lee::PrivateKey,
    config: &GenesisConfig,
) -> (lee::V03State, Vec<LeeTransaction>) {
    let mut state = build_initial_state(config.cross_zone.is_some());

    // Config txs seed the config accounts by transaction, so every node
    // reconstructs them by replaying the genesis block. Every cross-zone config
    // is initialized: each builtin has a user-callable InitConfig, so a default
    // config PDA would be claimable by the first initializer. The inbox's is
    // receiving-zones-only.
    let cross_zone_declared = config.cross_zone.as_ref();
    assert!(
        cross_zone_declared.is_some() || bridge_lock_holdings(&config.actions).next().is_none(),
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
    let inbox_config_tx =
        cross_zone_declared.map(|_| cross_zone::build_inbox_init_config_tx(config.channel_id));
    let supply_txs = config
        .actions
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

    let staked = founding_stakes(&config.actions);
    let bootstrap_stake_txs =
        build_stake_genesis_transactions(&staked, config.channel_params.minimum_sequencer_stake);

    let mut genesis_txs: Vec<_> = std::iter::once(build_init_channel_params_transaction(
        config.channel_params,
        config.channel_id,
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
        || AccountId::from(&PublicKey::new_from_private_key(signing_key)),
        |stake| AccountId::from(&stake.owner),
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

/// Whether `actions` stake any founding sequencer.
#[must_use]
pub fn stakes_any_sequencer(actions: &[GenesisAction]) -> bool {
    actions
        .iter()
        .any(|action| matches!(action, GenesisAction::StakeSequencer { .. }))
}

/// A solo channel creator's own genesis stake, owned by `ownership_key`.
///
/// It is the only stake, so it is the first to sign with the funding key.
#[must_use]
pub fn self_stake(
    sequencer_key: SequencerKey,
    ownership_key: &lee::PrivateKey,
    minimum_stake: u128,
) -> GenesisAction {
    GenesisAction::StakeSequencer {
        sequencer_key,
        ownership_public_key: PublicKey::new_from_private_key(ownership_key),
        stake_signature: sign_genesis_stake(0, sequencer_key, ownership_key, minimum_stake),
    }
}

/// The keys of the sequencers `actions` stake, `own_key` first because channel
/// creation gives the turn to index 0.
///
/// [`None`] when `actions` stake no sequencer.
#[must_use]
pub fn founding_committee(
    actions: &[GenesisAction],
    own_key: SequencerKey,
) -> Option<Vec<SequencerKey>> {
    let mut keys: Vec<_> = founding_stakes(actions)
        .into_iter()
        .map(|stake| stake.key)
        .collect();
    if keys.is_empty() {
        return None;
    }
    keys.sort_unstable();
    keys.retain(|key| *key != own_key);

    Some(std::iter::once(own_key).chain(keys).collect())
}

#[must_use]
pub fn genesis_stake_funding_account() -> AccountId {
    let key = lee::PrivateKey::try_new(GENESIS_STAKE_FUNDING_KEY)
        .expect("GENESIS_STAKE_FUNDING_KEY is a valid private key");
    AccountId::from(&PublicKey::new_from_private_key(&key))
}

/// The exact `Stake` message the founding sequencer at `index` must sign. Shared
/// offchain by the genesis sequencer.
#[must_use]
pub fn genesis_stake_message(
    index: usize,
    sequencer_key: SequencerKey,
    ownership_id: AccountId,
    minimum_stake: u128,
) -> lee::public_transaction::Message {
    let amount = minimum_stake;
    let mover_instruction_data = lee::program::Program::serialize_instruction(
        authenticated_transfer_core::Instruction::Transfer { amount },
    )
    .expect("Failed to serialize genesis mover instruction");
    // A nonce counts how many times an account has signed. The deposit that
    // funds this account needs no signature from it, so its count starts at 0.
    let funding_nonce = u128::try_from(index).expect("founding sequencer count fits in u128");

    lee::public_transaction::Message::try_new(
        programs::sequencer_stake().id().into(),
        vec![
            genesis_stake_funding_account(),
            ownership_id,
            system_accounts::stake_funds_account_id(&ownership_id),
            system_accounts::sequencer_stake_config_account_id(),
        ],
        vec![Nonce(funding_nonce), Nonce(0)],
        sequencer_stake_core::Instruction::Stake {
            sequencer_key,
            amount,
            mover_account_id: programs::authenticated_transfer().id().into(),
            mover_instruction_data,
        },
    )
    .expect("Failed to build genesis Stake message")
}

/// Signs the founding sequencer at `index`'s genesis `Stake`, for an operator
/// producing their [`GenesisAction::StakeSequencer`] entry.
#[must_use]
pub fn sign_genesis_stake(
    index: usize,
    sequencer_key: SequencerKey,
    ownership_key: &lee::PrivateKey,
    minimum_stake: u128,
) -> Signature {
    let ownership_id = AccountId::from(&PublicKey::new_from_private_key(ownership_key));
    let message = genesis_stake_message(index, sequencer_key, ownership_id, minimum_stake);
    Signature::new(ownership_key, &message.hash())
}

/// Bridge-lock holder balances configured for this zone's genesis.
fn bridge_lock_holdings(genesis: &[GenesisAction]) -> impl Iterator<Item = (AccountId, u64)> + '_ {
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

    let funding_key = lee::PrivateKey::try_new(GENESIS_STAKE_FUNDING_KEY).unwrap();
    let funding_public_key = PublicKey::new_from_private_key(&funding_key);
    let amount = u64::try_from(minimum_stake).expect("minimum sequencer stake exceeds u64");

    // One deposit per stake, so no total has to fit `u64`. They precede the
    // stakes because each one funds the account the stakes draw on.
    let mut txs: Vec<_> = staked
        .iter()
        .map(|stake| {
            build_supply_account_genesis_transaction(
                &genesis_stake_funding_account(),
                amount,
                genesis_deposit_op_id(stake.genesis_index),
            )
        })
        .collect();

    for (index, stake) in staked.iter().enumerate() {
        let ownership_id = AccountId::from(&stake.owner);
        let stake_message = genesis_stake_message(index, stake.key, ownership_id, minimum_stake);
        let stake_witness_set = lee::public_transaction::WitnessSet::from_raw_parts(vec![
            (
                Signature::new(&funding_key, &stake_message.hash()),
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
    channel_params: ChannelParams,
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
