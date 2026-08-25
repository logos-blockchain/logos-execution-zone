use bridge_core::Instruction;
use lee_core::program::{ProgramInput, ProgramOutput, read_lee_inputs};

/// Keeps the receipt's own slot non-empty so it survives pruning; its value is never read.
const RECEIPT_MARKER: u8 = 1;

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction,
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    assert!(
        caller_program_id.is_none(),
        "Bridge cannot be invoked through chain calls"
    );

    let post_states = match instruction {
        Instruction::Deposit {
            l1_deposit_op_id,
            native_program,
            recipient_id,
            amount,
        } => {
            let [bridge, recipient, receipt] = <[_; 3]>::try_from(pre_states.clone())
                .expect("Deposit requires exactly 3 accounts");

            assert_eq!(
                bridge.account_id,
                bridge_core::compute_bridge_account_id(self_program_id),
                "First account must be bridge PDA"
            );

            assert_eq!(
                recipient.account_id, recipient_id,
                "Second account must be the recipient"
            );

            assert_eq!(
                receipt.account_id,
                bridge_core::deposit_receipt_account_id(self_program_id, l1_deposit_op_id),
                "Third account must be the deposit-receipt PDA"
            );

            // Replay protection: the receipt PDA holds a bridge slot iff this op
            // id was already minted. On replay the slot is present and the whole
            // instruction is a no-op.
            //
            // Observability note: a no-op replay and a real first mint are both
            // successful txs, so an indexer cannot tell "credited here" from
            // "already credited by a peer" without deriving the receipt id and
            // checking whether its bridge slot existed before this block — that
            // slot is the only on-chain signal. Relevant once the explorer
            // surfaces deposits.
            if receipt.account.slot(self_program_id).is_some() {
                pre_states.iter().map(|pre| pre.account.clone()).collect()
            } else {
                let mut receipt_post = receipt.account;
                receipt_post.slot_mut(self_program_id).data = vec![RECEIPT_MARKER]
                    .try_into()
                    .expect("marker fits in account data");

                let mut bridge_post = bridge.account;
                let bridge_slot = bridge_post.slot_mut(self_program_id);
                bridge_slot.balance = bridge_slot
                    .balance
                    .checked_sub(u128::from(amount))
                    .expect("Bridge has insufficient balance");
                bridge_post.prune();

                let mut recipient_post = recipient.account;
                let recipient_slot = recipient_post.slot_mut(native_program);
                recipient_slot.balance = recipient_slot
                    .balance
                    .checked_add(u128::from(amount))
                    .expect("Recipient balance overflow");
                recipient_post.prune();

                vec![bridge_post, recipient_post, receipt_post]
            }
        }
        Instruction::Withdraw {
            amount: _,
            bedrock_account_pk: _,
        } => {
            panic!("Withdraws are disabled in the current version of LEZ");
        }
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        pre_states,
        post_states,
    )
    .write();
}
