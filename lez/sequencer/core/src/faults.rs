//! Slashable faults in a channel update.

use chain_state::AcceptOutcome;
use sequencer_slasher_actor::{Fault, ReportedOffence};

use crate::{Ed25519PublicKey, MsgId};

/// How the final tier took one finalized entry carrying a block.
pub struct Finalized {
    pub msg: MsgId,
    pub outcome: AcceptOutcome,
    /// It was the lineage's next entry past a finalized block, so its block
    /// had to follow the final tip.
    pub next: bool,
}

/// Every offence an update proves; `signers` names who wrote each finalized entry.
pub fn judge(
    undecodable: &[(MsgId, Ed25519PublicKey)],
    finalized: &[Finalized],
    signers: &[(MsgId, Ed25519PublicKey)],
) -> Vec<ReportedOffence> {
    let not_blocks = undecodable
        .iter()
        .map(|(inscription, signer)| offence(*inscription, *signer, Fault::NotABlock));
    let bad_blocks = finalized.iter().filter_map(|entry| {
        let AcceptOutcome::Parked(err) = &entry.outcome else {
            return None;
        };
        if !entry.next {
            return None;
        }
        let fault = if err.is_invalid_block() {
            Fault::InvalidBlock
        } else {
            Fault::MisplacedBlock
        };
        let (_, signer) = signers.iter().find(|(msg, _)| *msg == entry.msg)?;
        Some(offence(entry.msg, *signer, fault))
    });

    not_blocks.chain(bad_blocks).collect()
}

fn offence(inscription: MsgId, signer: Ed25519PublicKey, fault: Fault) -> ReportedOffence {
    ReportedOffence {
        signer: signer.to_bytes(),
        inscription: inscription.into(),
        fault,
    }
}

#[cfg(test)]
mod tests {
    use chain_state::BlockIngestError;
    use logos_blockchain_key_management_system_service::keys::Ed25519Key;

    use super::*;

    fn signer() -> Ed25519PublicKey {
        Ed25519Key::from_bytes(&[3; 32]).public_key()
    }

    fn msg(n: u8) -> MsgId {
        MsgId::from([n; 32])
    }

    fn finalized(n: u8, outcome: AcceptOutcome, next: bool) -> Finalized {
        Finalized {
            msg: msg(n),
            outcome,
            next,
        }
    }

    #[test]
    fn only_a_parked_next_block_is_an_offence() {
        let wrong_id = BlockIngestError::UnexpectedBlockId {
            expected: 5,
            got: 7,
        };
        let finalized = [
            finalized(1, AcceptOutcome::Applied(vec![]), true),
            finalized(2, AcceptOutcome::AlreadyApplied, true),
            finalized(
                3,
                AcceptOutcome::RetryableFailure(BlockIngestError::EmptyBlock),
                true,
            ),
            finalized(4, AcceptOutcome::Parked(BlockIngestError::EmptyBlock), true),
            finalized(5, AcceptOutcome::Parked(wrong_id.clone()), true),
            finalized(6, AcceptOutcome::Parked(wrong_id), false),
            finalized(
                7,
                AcceptOutcome::Parked(BlockIngestError::EmptyBlock),
                false,
            ),
        ];
        let signers: Vec<_> = (1..=7).map(|n| (msg(n), signer())).collect();

        assert_eq!(
            judge(&[(msg(9), signer())], &finalized, &signers),
            vec![
                offence(msg(9), signer(), Fault::NotABlock),
                offence(msg(4), signer(), Fault::InvalidBlock),
                offence(msg(5), signer(), Fault::MisplacedBlock),
            ]
        );
    }

    #[test]
    fn an_unsigned_block_is_no_offence() {
        let finalized = [finalized(
            1,
            AcceptOutcome::Parked(BlockIngestError::EmptyBlock),
            true,
        )];
        assert!(judge(&[], &finalized, &[]).is_empty());
    }
}
