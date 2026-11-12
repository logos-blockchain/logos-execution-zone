//! Slashable faults in a channel update.

use chain_state::{Judged, Verdict};
use sequencer_slasher_actor::protocol::{Fault, ReportedOffence};

use crate::{Ed25519PublicKey, MsgId};

/// Every offence an update proves; a finalized entry's `signer` is who wrote it.
#[must_use]
pub fn judge(undecodable: &[(MsgId, Ed25519PublicKey)], judged: &[Judged]) -> Vec<ReportedOffence> {
    let not_blocks = undecodable
        .iter()
        .map(|(inscription, signer)| offence(*inscription, signer.to_bytes(), Fault::NotABlock));
    let bad_blocks = judged.iter().filter_map(|entry| {
        let Verdict::Dropped { error, next: true } = &entry.verdict else {
            return None;
        };
        let fault = if error.is_invalid_block() {
            Fault::InvalidBlock
        } else {
            Fault::MisplacedBlock
        };
        Some(offence(entry.msg, entry.signer?, fault))
    });

    not_blocks.chain(bad_blocks).collect()
}

fn offence(inscription: MsgId, signer: [u8; 32], fault: Fault) -> ReportedOffence {
    ReportedOffence {
        signer,
        inscription: inscription.into(),
        fault,
    }
}

#[cfg(test)]
mod tests {
    use chain_state::BlockIngestError;
    use common::test_utils::produce_dummy_block;
    use logos_blockchain_key_management_system_service::keys::Ed25519Key;

    use super::*;

    fn signer() -> Ed25519PublicKey {
        Ed25519Key::from_bytes(&[3; 32]).public_key()
    }

    fn msg(n: u8) -> MsgId {
        MsgId::from([n; 32])
    }

    fn judged(n: u8, verdict: Verdict) -> Judged {
        Judged {
            msg: msg(n),
            signer: Some(signer().to_bytes()),
            block: produce_dummy_block(1, None, vec![]).digested(),
            verdict,
        }
    }

    fn dropped(error: BlockIngestError, next: bool) -> Verdict {
        Verdict::Dropped { error, next }
    }

    #[test]
    fn only_a_parked_next_block_is_an_offence() {
        let wrong_id = BlockIngestError::UnexpectedBlockId {
            expected: 5,
            got: 7,
        };
        let judged = [
            judged(1, Verdict::Settled),
            judged(
                2,
                Verdict::AlreadySettled(produce_dummy_block(1, None, vec![])),
            ),
            judged(4, dropped(BlockIngestError::EmptyBlock, true)),
            judged(5, dropped(wrong_id.clone(), true)),
            judged(6, dropped(wrong_id, false)),
            judged(7, dropped(BlockIngestError::EmptyBlock, false)),
        ];

        assert_eq!(
            judge(&[(msg(9), signer())], &judged),
            vec![
                offence(msg(9), signer().to_bytes(), Fault::NotABlock),
                offence(msg(4), signer().to_bytes(), Fault::InvalidBlock),
                offence(msg(5), signer().to_bytes(), Fault::MisplacedBlock),
            ]
        );
    }

    #[test]
    fn an_unsigned_block_is_no_offence() {
        let judged = [Judged {
            signer: None,
            ..judged(1, dropped(BlockIngestError::EmptyBlock, true))
        }];
        assert!(judge(&[], &judged).is_empty());
    }
}
