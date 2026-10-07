//! Genesis of a sequencer chain: the pre-genesis state and the genesis block every node replays.

use std::collections::BTreeMap;

use bridge_core::{BridgeAmount, DepositRecipient};
use common::{
    HashType,
    block::{Block, HashableBlockData},
    transaction::{FeePayee, LeeTransaction, TxEvents, clock_invocation, fee_invocation},
};
pub use cross_zone_inbox_core::CrossZoneConfig;
use lee::{
    AccountId, Actor, GENESIS_BLOCK_ID, PublicAccountEvidence, PublicKey, PublicTransaction,
    Signature, public_transaction::Message,
};
use lee_core::account::Nonce;
use sequencer_bridge::Credited;
use sequencer_stake_core::{ChannelParams, SequencerKey};
use serde::{Deserialize, Serialize};

/// Fixed, public key behind a genesis-only funding account.
///
/// The bridge can only be called top-level, not from `Stake`, so this
/// account is a pass-through that receives the genesis deposit and then moves
/// it into the real stake account. Not a secret: every node derives the same
/// account, and it holds nothing once genesis has run.
// TODO: replace the pass-through with a real Bedrock deposit, once that path
// exists. The genesis deposit funding it is synthetic, so this stays a fixed
// genesis-only key rather than a founding sequencer staking bridged funds.
pub const GENESIS_STAKE_FUNDING_KEY: [u8; 32] = [9; 32];

/// A transaction to be applied at genesis to supply initial balances.
///
/// Amounts are [`BridgeAmount`], not [`lee::Balance`]: every one is funded through the bridge's
/// `Deposit`, so it has the bridge's range, while the balance it credits stays a `Balance`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GenesisAction {
    SupplyAccount {
        recipient: DepositRecipient,
        balance: BridgeAmount,
    },
    /// Credits a private address with a pending native credit, published under the recovery
    /// binding the initial state pins for it; its owner receives it.
    SupplyPrivateAccount {
        address: AccountId,
        balance: BridgeAmount,
    },
    /// Funds a holder's holding PDA at genesis with one replayable genesis
    /// credit; the balance-only PDA needs no claim.
    SupplyBridgeLockHolding {
        holder: AccountId,
        amount: BridgeAmount,
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
pub struct GenesisSpec {
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

/// The genesis block and state `spec` describes.
#[must_use]
pub fn genesis_block_and_state(spec: &GenesisSpec) -> (Block, lee::V03State, Vec<TxEvents>) {
    let (genesis_state, genesis_txs, genesis_events) = build_genesis_state(spec);
    let genesis_block = HashableBlockData {
        reverted: Vec::new(),
        block_id: GENESIS_BLOCK_ID,
        transactions: genesis_txs,
        prev_block_hash: HashType([0; 32]),
        timestamp: 0,
    }
    .into_pending_block();

    (genesis_block, genesis_state, genesis_events)
}

/// Builds the initial genesis state from [`build_initial_state`] plus the
/// configured genesis transactions.
///
/// Returns the final state, the list of [`LeeTransaction`]s that should be
/// committed to the genesis block so external observers can replay them, and the
/// events they emitted.
#[must_use]
pub fn build_genesis_state(
    spec: &GenesisSpec,
) -> (lee::V03State, Vec<LeeTransaction>, Vec<TxEvents>) {
    let mut state = build_initial_state(spec.cross_zone.is_some());
    let genesis_opening = chain_state::apply::opening_fee_state(&state);

    // Config txs seed the config accounts by transaction, so every node
    // reconstructs them by replaying the genesis block. Every cross-zone config
    // is initialized: each builtin has a user-callable InitConfig, so an empty
    // config actor state would be left for whoever calls it first. The inbox's is
    // receiving-zones-only.
    let cross_zone_declared = spec.cross_zone.as_ref();
    assert!(
        cross_zone_declared.is_some() || bridge_lock_holdings(&spec.actions).next().is_none(),
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
        cross_zone_declared.map(|_| cross_zone::build_inbox_init_config_tx(spec.channel_id));
    let supply_txs = spec
        .actions
        .iter()
        .enumerate()
        .filter_map(|(index, action)| {
            let index = u64::try_from(index).expect("genesis action count fits in u64");
            match action {
                GenesisAction::SupplyAccount { recipient, balance } => {
                    Some(build_supply_account_genesis_transaction(
                        recipient,
                        *balance,
                        genesis_deposit_op_id(index),
                    ))
                }
                GenesisAction::SupplyPrivateAccount { address, balance } => Some(
                    sequencer_bridge::deposit_tx(
                        genesis_deposit_op_id(index),
                        &Credited::Private(*address),
                        *balance,
                    )
                    .expect("Failed to serialize genesis deposit instruction"),
                ),
                GenesisAction::SupplyBridgeLockHolding { holder, amount } => {
                    Some(build_supply_account_genesis_transaction(
                        &DepositRecipient::Identified(PublicAccountEvidence::Pda {
                            program: programs::bridge_lock_account_id(),
                            seed: bridge_lock_core::holding_seed(&holder.into_value()),
                        }),
                        *amount,
                        genesis_deposit_op_id(index),
                    ))
                }
                // Stakes are built below.
                GenesisAction::StakeSequencer { .. } => None,
            }
        });

    let staked = founding_stakes(&spec.actions);
    let bootstrap_stake_txs =
        build_stake_genesis_transactions(&staked, spec.channel_params.minimum_sequencer_stake);

    // The genesis fee transaction credits the first staked sequencer's ownership account.
    //
    // A stakeless genesis (e.g. a sequencer reconstructing an existing channel
    // it did not bootstrap) has no staked account to reward, so it falls back to
    // the default account: this genesis is a throwaway placeholder (the real
    // one is replayed from the channel), the summary is the default, so the
    // credit is zero and the account is left untouched.
    let producer = staked
        .first()
        .map_or_else(AccountId::default, |stake| AccountId::from(&stake.owner));
    let genesis_summary = fee_core::BlockFeeSummary::default();
    let genesis_payout = chain_state::apply::block_payout(&genesis_opening, &genesis_summary);

    let genesis_txs: Vec<_> = std::iter::once(build_init_channel_params_transaction(
        spec.channel_params,
        spec.channel_id,
    ))
    .chain(cross_zone_config_txs)
    .chain(inbox_config_tx)
    .chain(supply_txs)
    .chain(bootstrap_stake_txs)
    .chain([
        fee_invocation(genesis_summary, genesis_payout, FeePayee::Present(producer)),
        clock_invocation(GENESIS_BLOCK_ID, 0),
    ])
    .collect();

    let events = genesis_txs
        .iter()
        .enumerate()
        .map(|(index, tx)| TxEvents {
            tx_index: index.try_into().expect("genesis tx count fits"),
            tx_hash: tx.hash().into(),
            events: state
                .transition_from_public_transaction(tx, GENESIS_BLOCK_ID, 0)
                .expect("Failed to execute genesis transaction"),
        })
        .collect();
    let genesis_txs = genesis_txs
        .into_iter()
        .map(LeeTransaction::Public)
        .collect();

    (state, genesis_txs, events)
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
) -> Message {
    let amount = minimum_stake;
    // A nonce counts how many times an account has signed. The deposit that
    // funds this account needs no signature from it, so its count starts at 0.
    let funding_nonce = u128::try_from(index).expect("founding sequencer count fits in u128");

    let sequencer_stake_program_id = programs::sequencer_stake_account_id();
    let ownership = Actor::new(ownership_id, sequencer_stake_program_id);
    Message {
        admission_evidence: vec![PublicAccountEvidence::Pda {
            program: sequencer_stake_program_id,
            seed: sequencer_stake_core::stake_funds_seed(&ownership_id),
        }],
        ..Message::try_new(
            ownership,
            vec![
                ownership,
                Actor::native_balance(system_accounts::stake_funds_account_id(&ownership_id)),
                Actor::native_balance(genesis_stake_funding_account()),
                Actor::new(
                    system_accounts::sequencer_stake_config_account_id(),
                    sequencer_stake_program_id,
                ),
            ],
            BTreeMap::from([
                (genesis_stake_funding_account(), Nonce(funding_nonce)),
                (ownership_id, Nonce(0)),
            ]),
            sequencer_stake_core::Message::Stake {
                sequencer_key,
                amount,
                has_record: false,
                funding: genesis_stake_funding_account(),
            },
        )
        .expect("Failed to build genesis Stake message")
    }
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
fn bridge_lock_holdings(
    genesis: &[GenesisAction],
) -> impl Iterator<Item = (AccountId, BridgeAmount)> + '_ {
    genesis.iter().filter_map(|action| match action {
        GenesisAction::SupplyBridgeLockHolding { holder, amount } => Some((*holder, *amount)),
        GenesisAction::SupplyAccount { .. }
        | GenesisAction::SupplyPrivateAccount { .. }
        | GenesisAction::StakeSequencer { .. } => None,
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
    let funding =
        DepositRecipient::Identified(PublicAccountEvidence::Key(funding_public_key.clone()));
    let amount =
        BridgeAmount::try_from(minimum_stake).expect("minimum sequencer stake exceeds u64");

    // One deposit per stake, so no total has to fit a `BridgeAmount`. They precede the
    // stakes because each one funds the account the stakes draw on.
    let mut txs: Vec<_> = staked
        .iter()
        .map(|stake| {
            build_supply_account_genesis_transaction(
                &funding,
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
    recipient: &DepositRecipient,
    amount: BridgeAmount,
    op_id: [u8; 32],
) -> PublicTransaction {
    sequencer_bridge::deposit_tx(op_id, &Credited::Public(recipient.evidence()), amount)
        .expect("Failed to serialize genesis deposit instruction")
}

/// Sets the channel posting params in the `sequencer_stake` config account.
/// Unsigned and replayable, so an indexer reconstructs it from the genesis
/// block rather than needing the sequencer's config.
fn build_init_channel_params_transaction(
    channel_params: ChannelParams,
    channel_id: [u8; 32],
) -> PublicTransaction {
    let config = Actor::new(
        system_accounts::sequencer_stake_config_account_id(),
        programs::sequencer_stake_account_id(),
    );
    let message = Message::try_new(
        config,
        vec![config],
        BTreeMap::new(),
        sequencer_stake_core::Message::InitChannelParams {
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
            GenesisAction::SupplyAccount { .. }
            | GenesisAction::SupplyPrivateAccount { .. }
            | GenesisAction::SupplyBridgeLockHolding { .. } => None,
        })
        .collect()
}
