use bridge_core::Instruction;
use lee_core::{
    account::Input,
    program::{ProgramInput, ProgramOutput, read_lee_inputs},
};

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

            // Positions need only name distinct slots, so the recipient may otherwise alias a
            // bridge-owned account: the credit would then land in a slot this program cannot
            // debit, stranding reserves against the L1 lock that backs them.
            assert_ne!(
                recipient.account_id, bridge.account_id,
                "Recipient must not be the bridge PDA"
            );
            assert_ne!(
                recipient.account_id, receipt.account_id,
                "Recipient must not be the deposit-receipt PDA"
            );

            // Replay protection: the receipt PDA holds this program's marker iff
            // this op id was already minted. The marker is the signal, not the
            // slot: rule 4 lets anyone credit a foreign slot into existence, but
            // only this program can write its data.
            //
            // Observability note: a no-op replay and a real first mint are both
            // successful txs, so an indexer cannot tell "credited here" from
            // "already credited by a peer" without deriving the receipt id and
            // checking whether its marker existed before this block — that
            // marker is the only on-chain signal. Relevant once the explorer
            // surfaces deposits.
            if receipt.data(self_program_id).is_empty() {
                let mut receipt_post = receipt.into_slot_of(self_program_id);
                receipt_post.data = vec![RECEIPT_MARKER]
                    .try_into()
                    .expect("marker fits in account data");

                let mut bridge_post = bridge.into_slot_of(self_program_id);
                bridge_post.balance = bridge_post
                    .balance
                    .checked_sub(u128::from(amount))
                    .expect("Bridge has insufficient balance");

                let mut recipient_post = recipient.into_caller_named_slot();
                recipient_post.balance = recipient_post
                    .balance
                    .checked_add(u128::from(amount))
                    .expect("Recipient balance overflow");

                vec![Some(bridge_post), Some(recipient_post), Some(receipt_post)]
            } else {
                pre_states.iter().map(Input::unchanged).collect()
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
