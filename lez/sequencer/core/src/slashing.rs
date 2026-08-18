//! Slashing of sequencers that inscribe a payload that is not a block.
//!
//! The approvals a `Slash` carries are its only authorization.

use std::{
    collections::BTreeSet,
    sync::{Arc, RwLock},
};

use anyhow::{Context as _, Result};
use common::transaction::LeeTransaction;
use lee::{AccountId, PublicTransaction, public_transaction::Message};
use log::{error, warn};
use logos_blockchain_zone_sdk::Slot;
use kameo::actor::ActorRef;
use sequencer_stake_core::{SequencerKey, SlashApproval};
use sequencer_storage_actor::{
    StorageActorTrait,
    protocol::{GetSlashRecordBytes, PutSlashRecordBytes},
};

use crate::block_publisher::{BlockPublisherTrait, Ed25519Key, MsgId};

/// Offending inscriptions, before and after the writer is known.
#[derive(Clone, Default)]
pub(crate) struct SlashRecord {
    state: Arc<RwLock<Offences>>,
}

#[derive(Debug, Default, borsh::BorshSerialize, borsh::BorshDeserialize)]
struct Offences {
    /// Reported by the follow path, still to be attributed to a writer.
    unattributed: BTreeSet<([u8; 32], u64)>,
    /// Never removed: an offending key stays liable for good.
    found: BTreeSet<(SequencerKey, [u8; 32])>,
}

impl SlashRecord {
    /// Restores the persisted record, empty if none was written.
    pub(crate) async fn load<S: StorageActorTrait>(storage_ref: &ActorRef<S>) -> Self {
        let state = storage_ref
            .ask(GetSlashRecordBytes)
            .await
            .expect("Failed to read the slash record from store")
            .map_or_else(Offences::default, |bytes| {
                borsh::from_slice(&bytes)
                    .expect("persisted slash record should decode with this build")
            });
        Self {
            state: Arc::new(RwLock::new(state)),
        }
    }

    /// Records what the follow path saw. Attribution happens later, so this reads
    /// no L1.
    pub(crate) async fn report<S: StorageActorTrait>(
        &self,
        storage_ref: &ActorRef<S>,
        undecodable: &[(MsgId, Slot)],
    ) {
        if undecodable.is_empty() {
            return;
        }
        let bytes = {
            let mut offences = self.state.write().expect("slash record lock poisoned");
            for (msg_id, slot) in undecodable {
                error!(
                    "Undecodable inscription {msg_id} at slot {}",
                    slot.into_inner()
                );
                offences
                    .unattributed
                    .insert(((*msg_id).into(), slot.into_inner()));
            }
            encoded(&offences)
        };
        persist(storage_ref, bytes).await;
    }

    fn unattributed(&self) -> Vec<([u8; 32], u64)> {
        self.state
            .read()
            .expect("slash record lock poisoned")
            .unattributed
            .iter()
            .copied()
            .collect()
    }

    async fn attribute<S: StorageActorTrait>(
        &self,
        storage_ref: &ActorRef<S>,
        inscription: [u8; 32],
        slot: u64,
        offender: SequencerKey,
    ) {
        let bytes = {
            let mut offences = self.state.write().expect("slash record lock poisoned");
            offences.unattributed.remove(&(inscription, slot));
            offences.found.insert((offender, inscription));
            encoded(&offences)
        };
        persist(storage_ref, bytes).await;
    }

    pub(crate) fn all(&self) -> Vec<(SequencerKey, [u8; 32])> {
        self.state
            .read()
            .expect("slash record lock poisoned")
            .found
            .iter()
            .copied()
            .collect()
    }

}

fn encoded(offences: &Offences) -> Vec<u8> {
    borsh::to_vec(offences).expect("slash record should serialize")
}

/// Fatal on failure: the checkpoint is about to move past the offence.
async fn persist<S: StorageActorTrait>(storage_ref: &ActorRef<S>, bytes: Vec<u8>) {
    storage_ref
        .ask(PutSlashRecordBytes { bytes })
        .await
        .unwrap_or_else(|err| panic!("Failed to persist the slash record: {err}"));
}

/// Asks L1 who wrote each offence. Anything unattributed stays for the next turn.
pub(crate) async fn attribute_offences<BP: BlockPublisherTrait, S: StorageActorTrait>(
    publisher: &BP,
    record: &SlashRecord,
    storage_ref: &ActorRef<S>,
) -> Result<()> {
    for (inscription, slot) in record.unattributed() {
        let signer = publisher
            .inscription_signer(Slot::from(slot), MsgId::from(inscription))
            .await
            .context("Failed to attribute an offending inscription")?;
        let Some(offender) = signer.and_then(|signer| SequencerKey::new(signer.to_bytes())) else {
            warn!("No signer to attribute the inscription at slot {slot} to");
            continue;
        };

        error!(
            "Inscription at slot {slot} attributed to {}",
            hex::encode(offender)
        );
        record.attribute(storage_ref, inscription, slot, offender).await;
    }

    Ok(())
}

/// A `Slash` for every offence whose key still has stake, approved by this node.
#[must_use]
pub(crate) fn slash_candidates(
    state: &lee::V03State,
    record: &SlashRecord,
    approver: &Ed25519Key,
) -> Vec<LeeTransaction> {
    let Some(config) = crate::committee_discovery::read_config(state) else {
        return Vec::new();
    };
    // Only an accredited key's approval counts.
    if !config.entries.contains_key(&approver_key(approver)) {
        return Vec::new();
    }

    // One burn takes the whole stake, so keep one offence per offender.
    let mut offences = record.all();
    offences.dedup_by_key(|(offender, _)| *offender);

    offences
        .into_iter()
        .filter_map(|(offender, inscription)| {
            let entry = config.entries.get(&offender)?;
            build_slash_tx(
                entry.account_id,
                offender,
                inscription,
                vec![approve(approver, offender, inscription)],
            )
            .inspect_err(|err| warn!("Failed to build a Slash tx: {err:#}"))
            .ok()
        })
        .collect()
}

/// This node's signature over an offence. Peers supply the rest over gossip.
#[must_use]
fn approve(
    approver: &Ed25519Key,
    sequencer_key: SequencerKey,
    inscription: [u8; 32],
) -> SlashApproval {
    let message = sequencer_stake_core::slash_approval_message(sequencer_key, inscription);
    SlashApproval {
        signer: approver_key(approver),
        signature: approver.sign_payload(&message).to_bytes().to_vec(),
    }
}

#[must_use]
fn approver_key(approver: &Ed25519Key) -> SequencerKey {
    SequencerKey::new(approver.public_key().to_bytes())
        .expect("a Bedrock public key is a valid Ed25519 public key")
}

// No witness set: the approvals are the authorization.
pub(crate) fn build_slash_tx(
    ownership_id: AccountId,
    sequencer_key: SequencerKey,
    inscription: [u8; 32],
    approvals: Vec<SlashApproval>,
) -> Result<LeeTransaction> {
    let program_id = programs::sequencer_stake().id();
    let message = Message::try_new(
        program_id,
        vec![
            ownership_id,
            sequencer_stake_core::slash_sink_account_id(program_id),
            system_accounts::sequencer_stake_config_account_id(),
        ],
        vec![],
        sequencer_stake_core::Instruction::Slash {
            sequencer_key,
            inscription,
            approvals,
        },
    )
    .context("Failed to build a Slash message")?;

    Ok(LeeTransaction::Public(PublicTransaction::new(
        message,
        lee::public_transaction::WitnessSet::from_raw_parts(vec![]),
    )))
}

#[cfg(test)]
#[cfg(feature = "mock")]
mod tests {
    use kameo::actor::Spawn as _;
    use lee_core::account::Account;
    use logos_blockchain_core::mantle::ops::channel::ChannelId;
    use logos_blockchain_key_management_system_service::keys::Ed25519Key;
    use sequencer_stake_core::{SequencerEntry, SequencerStakeConfig};
    use sequencer_storage_actor::mock::MockStorageActor;

    use super::*;
    use crate::mock::MockBlockPublisher;

    /// A storage actor that holds no record and accepts every write.
    fn storage() -> ActorRef<MockStorageActor> {
        let mut mock = MockStorageActor::new();
        mock.expect_handle_get_slash_record_bytes()
            .returning(|_, _| Ok(None));
        mock.expect_handle_put_slash_record_bytes()
            .returning(|_, _| Ok(()));
        MockStorageActor::spawn(mock)
    }

    const INSCRIPTION: [u8; 32] = [7; 32];
    const SLOT: u64 = 42;

    fn offender_signing_key() -> Ed25519Key {
        Ed25519Key::from_bytes(&[3; 32])
    }

    fn offender() -> SequencerKey {
        SequencerKey::new(offender_signing_key().public_key().to_bytes()).expect("valid key")
    }

    fn publisher(attributes: bool) -> MockBlockPublisher {
        let publisher =
            MockBlockPublisher::with_canned_channel(ChannelId::from([0; 32]), None, Vec::new());
        if attributes {
            publisher.with_inscription_signer(offender_signing_key().public_key())
        } else {
            publisher
        }
    }

    async fn reported() -> SlashRecord {
        let record = SlashRecord::default();
        record
            .report(&storage(), &[(MsgId::from(INSCRIPTION), Slot::from(SLOT))])
            .await;
        record
    }

    /// State whose config account accredits `key` with a stake to burn.
    fn state_staking(key: SequencerKey, ownership_id: AccountId) -> lee::V03State {
        let config = Account {
            program_owner: programs::sequencer_stake().id().into(),
            data: SequencerStakeConfig {
                minimum_sequencer_stake: 1,
                entries: [(
                    key,
                    SequencerEntry {
                        account_id: ownership_id,
                        total_staked: 1,
                        total_pending_unstake: 0,
                    },
                )]
                .into(),
            }
            .to_bytes()
            .try_into()
            .expect("config fits"),
            ..Account::default()
        };
        lee::V03State::new()
            .with_public_accounts([(system_accounts::sequencer_stake_config_account_id(), config)])
    }

    #[tokio::test]
    async fn a_reported_offence_is_attributed_to_its_writer() {
        let record = reported().await;
        // Reporting alone names nobody, so there is nothing to slash yet.
        assert!(record.all().is_empty());

        attribute_offences(&publisher(true), &record, &storage())
            .await
            .expect("attribute");
        assert_eq!(record.all(), vec![(offender(), INSCRIPTION)]);
    }

    #[tokio::test]
    async fn an_unattributable_offence_is_kept_for_the_next_turn() {
        let record = reported().await;
        attribute_offences(&publisher(false), &record, &storage())
            .await
            .expect("attribute");
        assert!(record.all().is_empty());

        // Still on record, so a later turn can name it.
        attribute_offences(&publisher(true), &record, &storage())
            .await
            .expect("attribute");
        assert_eq!(record.all(), vec![(offender(), INSCRIPTION)]);
    }

    #[tokio::test]
    async fn nothing_is_reported_for_an_empty_report() {
        let record = SlashRecord::default();
        record.report(&storage(), &[]).await;
        assert!(record.all().is_empty());
    }

    #[tokio::test]
    async fn one_offender_yields_one_slash_however_many_offences() {
        let record = SlashRecord::default();
        record
            .report(
                &storage(),
                &[
                    (MsgId::from(INSCRIPTION), Slot::from(SLOT)),
                    (MsgId::from([9; 32]), Slot::from(SLOT)),
                ],
            )
            .await;
        attribute_offences(&publisher(true), &record, &storage())
            .await
            .expect("attribute");
        assert_eq!(record.all().len(), 2);

        // The first burn takes everything, so the second would only abort.
        let state = state_staking(offender(), AccountId::new([8; 32]));
        assert_eq!(
            slash_candidates(&state, &record, &offender_signing_key()).len(),
            1
        );
    }

    #[tokio::test]
    async fn only_an_offender_with_stake_left_is_a_candidate() {
        let record = reported().await;
        attribute_offences(&publisher(true), &record, &storage())
            .await
            .expect("attribute");

        // An unaccredited approver proposes nothing.
        let outsider = Ed25519Key::from_bytes(&[9; 32]);
        let state = state_staking(offender(), AccountId::new([8; 32]));
        assert!(slash_candidates(&state, &record, &outsider).is_empty());

        let candidates = slash_candidates(&state, &record, &offender_signing_key());
        assert_eq!(candidates.len(), 1);

        // Nothing left to burn once the entry is gone.
        let empty = lee::V03State::new();
        assert!(slash_candidates(&empty, &record, &offender_signing_key()).is_empty());
    }
}
