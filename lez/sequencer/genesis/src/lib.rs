//! Genesis of a sequencer chain: the pre-genesis state and the genesis block every node replays.

use std::collections::BTreeMap;

use bridge_core::{BridgeAmount, DepositRecipient};
use common::{
    HashType,
    block::{Block, HashableBlockData, TransactionReceipt},
    transaction::{FeePayee, LeeTransaction, TxEvents, clock_invocation, fee_invocation},
};
use lee::{
    AccountId, Actor, GENESIS_BLOCK_ID, PublicAccountEvidence, PublicTransaction,
    public_transaction::{Message, WitnessEntry},
    signature::{
        INITIAL_KEY_TYPE, PublicAccountSecret, Signer, authenticate, current_key, initial_key,
        public_account_id,
    },
};
use lee_core::{account::Nonce, signing_key::SigningKeyState};
use sequencer_bridge::Credited;
use sequencer_stake_core::{ChannelParams, SequencerKey};
use serde::{Deserialize, Serialize};

mod hex_witness_entry {
    use lee::public_transaction::WitnessEntry;
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct HexWitnessEntry {
        auth_data: String,
        next: String,
    }

    pub fn serialize<S: Serializer>(
        entry: &WitnessEntry,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        HexWitnessEntry {
            auth_data: hex::encode(&entry.auth_data),
            next: hex::encode(
                borsh::to_vec(&entry.next).expect("a signing key state encodes to 33 bytes"),
            ),
        }
        .serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<WitnessEntry, D::Error> {
        let HexWitnessEntry { auth_data, next } = HexWitnessEntry::deserialize(deserializer)?;
        Ok(WitnessEntry {
            auth_data: hex::decode(auth_data).map_err(D::Error::custom)?,
            next: borsh::from_slice(&hex::decode(next).map_err(D::Error::custom)?)
                .map_err(D::Error::custom)?,
        })
    }
}

/// Fixed, public secret behind a genesis-only funding account, the id of its nonce-0 key.
///
/// The bridge can only be called top-level, not from `Stake`, so this
/// account is a pass-through that receives the genesis deposit and then moves
/// it into the real stake account. Not kept secret: every node derives the same
/// account, and it holds nothing once genesis has run.
// TODO: replace the pass-through with a real Bedrock deposit, once that path
// exists. The genesis deposit funding it is synthetic, so this stays a fixed
// genesis-only key rather than a founding sequencer staking bridged funds.
pub const GENESIS_STAKE_FUNDING_KEY: PublicAccountSecret = PublicAccountSecret::new([9; 32]);

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
    /// Stakes `sequencer_key` at genesis.
    StakeSequencer {
        sequencer_key: SequencerKey,
        /// The account owning the stake.
        ownership_id: AccountId,
        /// The ownership account's witness entry for its genesis `Stake`, from
        /// `sign_genesis_stake`: `{"auth_data": hex, "next": hex}`, the next key in its 33-byte
        /// encoding (key type byte, then key commitment). At nonce 0, `auth_data` starts with
        /// the account's initial key.
        #[serde(with = "hex_witness_entry")]
        stake_entry: WitnessEntry,
    },
}

/// Everything a chain's genesis is built from.
#[derive(Clone, Debug)]
pub struct GenesisSpec {
    pub channel_id: [u8; 32],
    pub channel_params: ChannelParams,
    /// Applied in order, founding stakes included.
    pub actions: Vec<GenesisAction>,
}

/// A founding sequencer's key, plus the ownership account attesting to its stake.
struct FoundingStake {
    /// Index of the `StakeSequencer` action configuring this stake, which names
    /// the genesis deposit funding it.
    genesis_index: u64,
    key: SequencerKey,
    owner: AccountId,
    entry: WitnessEntry,
}

/// The pre-genesis state: `testnet_initial_state`, nothing else. Everything is
/// applied as genesis transactions in [`build_genesis_state`] so followers replay it.
#[must_use]
pub fn build_initial_state() -> lee::V03State {
    let base = testnet_initial_state::initial_state();

    // Stamped on fresh genesis and restore-replay: compare against the
    // indexer's on divergence.
    tracing::info!(
        fingerprint = %hex::encode(base.genesis_fingerprint()),
        "Genesis fingerprint"
    );
    base
}

/// The genesis block and state `spec` describes.
#[must_use]
pub fn genesis_block_and_state(spec: &GenesisSpec) -> (Block, lee::V03State, Vec<TxEvents>) {
    let (genesis_state, genesis_txs, genesis_events) = build_genesis_state(spec);
    // Every genesis transaction but the trailing fee and clock ones is exempt.
    let receipts = vec![TransactionReceipt::EXEMPT; genesis_txs.len().saturating_sub(2)];
    let genesis_block = HashableBlockData {
        receipts,
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
    let mut state = build_initial_state();
    let genesis_opening = chain_state::apply::opening_fee_state(&state);

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
        .map_or_else(AccountId::default, |stake| stake.owner);
    let genesis_summary = fee_core::BlockFeeSummary::default();
    let genesis_payout = chain_state::apply::block_payout(&genesis_opening, &genesis_summary);

    let genesis_txs: Vec<_> = std::iter::once(build_init_channel_params_transaction(
        spec.channel_params,
        spec.channel_id,
    ))
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

/// A solo channel creator's own genesis stake, owned by `ownership_secret`.
///
/// It is the only stake, so it is the first to sign with the funding key.
#[must_use]
pub fn self_stake(
    sequencer_key: SequencerKey,
    ownership_secret: &PublicAccountSecret,
    minimum_stake: u128,
) -> GenesisAction {
    GenesisAction::StakeSequencer {
        sequencer_key,
        ownership_id: public_account_id(ownership_secret),
        stake_entry: sign_genesis_stake(0, sequencer_key, ownership_secret, minimum_stake),
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
    public_account_id(&GENESIS_STAKE_FUNDING_KEY)
}

/// The genesis funding account as a signer at its nonce in `message`.
fn genesis_stake_funding_signer(message: &Message) -> Signer {
    let nonce = message.nonces[&genesis_stake_funding_account()];
    Signer::new(
        &GENESIS_STAKE_FUNDING_KEY,
        nonce,
        INITIAL_KEY_TYPE,
        INITIAL_KEY_TYPE,
    )
}

/// What both signers of a genesis `Stake` sign: `message` with the funding account's next key
/// and the owner's `owner_next`, in `nonces` order.
#[must_use]
pub fn genesis_stake_message_with_keys(
    message: &Message,
    ownership_id: AccountId,
    owner_next: SigningKeyState,
) -> [u8; 32] {
    let next_keys: Vec<_> = BTreeMap::from([
        (
            genesis_stake_funding_account(),
            genesis_stake_funding_signer(message).next(),
        ),
        (ownership_id, owner_next),
    ])
    .into_values()
    .collect();
    message.message_with_keys(&next_keys)
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
///
/// Signs with the ownership account's nonce-0 key, rotating to its nonce-1 key.
#[must_use]
pub fn sign_genesis_stake(
    index: usize,
    sequencer_key: SequencerKey,
    ownership_secret: &PublicAccountSecret,
    minimum_stake: u128,
) -> WitnessEntry {
    let owner = Signer::new(
        ownership_secret,
        Nonce(0),
        INITIAL_KEY_TYPE,
        INITIAL_KEY_TYPE,
    );
    let ownership_id = owner.account_id();
    let message = genesis_stake_message(index, sequencer_key, ownership_id, minimum_stake);
    let message_with_keys = genesis_stake_message_with_keys(&message, ownership_id, owner.next());
    WitnessEntry {
        auth_data: owner.auth_data(&message_with_keys),
        next: owner.next(),
    }
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

    let funding = DepositRecipient::Identified(PublicAccountEvidence::Key(initial_key(
        &GENESIS_STAKE_FUNDING_KEY,
    )));
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
        let ownership_id = stake.owner;
        let stake_message = genesis_stake_message(index, stake.key, ownership_id, minimum_stake);
        let message_with_keys =
            genesis_stake_message_with_keys(&stake_message, ownership_id, stake.entry.next);

        // Redundant with the authentication every tx gets, but names the entry.
        assert!(
            current_key(None, ownership_id, &stake.entry.auth_data)
                .and_then(|(current, signature)| authenticate(
                    &current,
                    &message_with_keys,
                    signature,
                    &stake.entry.next
                ))
                .is_ok(),
            "genesis stake signature does not match founding sequencer {index} ({})",
            hex::encode(stake.key)
        );

        let funding_signer = genesis_stake_funding_signer(&stake_message);
        let funding_entry = WitnessEntry {
            auth_data: funding_signer.auth_data(&message_with_keys),
            next: funding_signer.next(),
        };
        // Witness entries follow `nonces` order.
        let stake_witness_set = lee::public_transaction::WitnessSet::from_raw_parts(
            BTreeMap::from([
                (genesis_stake_funding_account(), funding_entry),
                (ownership_id, stake.entry.clone()),
            ])
            .into_values()
            .collect(),
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
                ownership_id,
                stake_entry,
            } => {
                let index = u64::try_from(index).expect("genesis action count fits in u64");
                Some(FoundingStake {
                    genesis_index: index,
                    key: *sequencer_key,
                    owner: *ownership_id,
                    entry: stake_entry.clone(),
                })
            }
            GenesisAction::SupplyAccount { .. } | GenesisAction::SupplyPrivateAccount { .. } => {
                None
            }
        })
        .collect()
}
