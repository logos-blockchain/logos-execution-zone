use lee_core::{
    account::{Account, AccountWithMetadata, Data},
    program::{AccountPostState, ChainedCall, PdaSeed},
};
use token_core::{TokenDefinition, TokenHolding};

pub fn transfer_to_private_associated_token_account(
    token_definition: AccountWithMetadata,
    senders: Vec<(AccountWithMetadata, PdaSeed, u128)>,
    recipient: AccountWithMetadata,
    recipient_seed: PdaSeed,
) -> (Vec<AccountPostState>, Vec<ChainedCall>) {
    let token_program_id = token_definition.account.program_owner;
    let definition = TokenDefinition::try_from(&token_definition.account.data)
        .expect("Token definition account must be valid");
    let mut holding =
        TokenHolding::zeroized_from_definition(token_definition.account_id, &definition);

    let mut chained_calls = vec![
        ChainedCall::new(
            token_program_id,
            vec![
                token_definition.clone(),
                AccountWithMetadata {
                    is_authorized: true,
                    ..recipient.clone()
                },
            ],
            &token_core::Instruction::InitializeAccount,
        )
        .with_pda_seeds(vec![recipient_seed]),
    ];

    let mut credited = AccountWithMetadata {
        account: Account {
            program_owner: token_program_id,
            data: Data::from(&holding),
            ..recipient.account.clone()
        },
        is_authorized: false,
        account_id: recipient.account_id,
    };

    let mut post_states = vec![AccountPostState::new(token_definition.account)];
    for (sender, seed, amount) in senders {
        post_states.push(AccountPostState::new(sender.account.clone()));
        chained_calls.push(
            ChainedCall::new(
                token_program_id,
                vec![
                    AccountWithMetadata {
                        is_authorized: true,
                        ..sender
                    },
                    credited.clone(),
                ],
                &token_core::Instruction::Transfer {
                    amount_to_transfer: amount,
                },
            )
            .with_pda_seeds(vec![seed]),
        );
        credit(&mut holding, amount);
        credited.account.data = Data::from(&holding);
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
