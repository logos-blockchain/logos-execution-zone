use lee_core::{
    account::{Account, AccountWithMetadata, Data},
    program::{AccountPostState, ChainedCall, PdaSeed},
};
use token_core::TokenHolding;

pub fn transfer_to_private_associated_token_account(
    token_definition: AccountWithMetadata,
    senders: Vec<(AccountWithMetadata, Option<PdaSeed>, u128)>,
    recipient: AccountWithMetadata,
    recipient_seed: PdaSeed,
) -> (Vec<AccountPostState>, Vec<ChainedCall>) {
    let token_program_id = token_definition.account.program_owner;

    let mut chained_calls = Vec::new();
    let mut post_states = vec![AccountPostState::new(token_definition.account)];
    let mut recipient_holding: Option<TokenHolding> = None;

    for (sender, seed, amount) in senders {
        post_states.push(AccountPostState::new(sender.account.clone()));

        let sender_holding = TokenHolding::try_from(&sender.account.data)
            .expect("Sender must hold a valid token holding");
        let recipient_pre = AccountWithMetadata {
            account: match &recipient_holding {
                Some(holding) => Account {
                    program_owner: token_program_id,
                    data: Data::from(holding),
                    ..recipient.account.clone()
                },
                None => recipient.account.clone(),
            },
            is_authorized: true,
            account_id: recipient.account_id,
        };

        let mut pda_seeds = vec![recipient_seed];
        let sender_pre = match seed {
            Some(seed) => {
                pda_seeds.push(seed);
                AccountWithMetadata {
                    is_authorized: true,
                    ..sender
                }
            }
            None => sender,
        };

        chained_calls.push(
            ChainedCall::new(
                token_program_id,
                vec![sender_pre, recipient_pre],
                &token_core::Instruction::Transfer {
                    amount_to_transfer: amount,
                },
            )
            .with_pda_seeds(pda_seeds),
        );

        let mut holding =
            recipient_holding.unwrap_or_else(|| TokenHolding::zeroized_clone_from(&sender_holding));
        credit(&mut holding, amount);
        recipient_holding = Some(holding);
    }
    post_states.push(AccountPostState::new(recipient.account));

    (post_states, chained_calls)
}

fn credit(holding: &mut TokenHolding, amount: u128) {
    match holding {
        TokenHolding::Fungible { balance, .. } => {
            *balance = balance
                .checked_add(amount)
                .expect("Recipient balance overflow");
        }
        TokenHolding::NftPrintedCopy { owned, .. } => {
            assert_eq!(amount, 1, "Invalid balance for NFT Printed Copy transfer");
            assert!(!*owned, "Recipient already owns the NFT Printed Copy");
            *owned = true;
        }
        TokenHolding::NftMaster { .. } => {
            panic!("Initialized holdings are never NFT masters")
        }
    }
}
