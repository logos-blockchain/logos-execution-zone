use lee_core::{
    account::ShardData,
    program::{AccountMeta, Plan, Proposed},
};
use token_core::{TokenDefinition, TokenDescriptor, TokenKind};

use crate::Effect;

pub fn initialize_account(
    plan: &mut Plan,
    definition_account: &AccountMeta,
    account_to_initialize: &AccountMeta,
    kind: TokenKind,
) {
    // The definition decides what the holding becomes, and the holding's resolver never sees it.
    // The guard on the definition is what turns the instruction's claimed kind into a fact.
    let kind = plan
        .require(
            definition_account,
            &Effect::CheckHoldingKind(kind),
            Proposed::new(kind),
        )
        .get();

    plan.update(
        account_to_initialize,
        &Effect::InitializeHolding {
            descriptor: TokenDescriptor {
                definition_id: definition_account.account_id,
                kind,
            },
            is_authorized: account_to_initialize.is_authorized,
        },
    );
}

pub fn check_holding_kind(pre_data: &ShardData, kind: TokenKind) {
    let definition = TokenDefinition::try_from(pre_data).expect("Definition account must be valid");

    assert_eq!(
        TokenKind::from_definition(&definition),
        kind,
        "Token Definition does not initialize this Token Holding kind"
    );
}

#[must_use]
pub fn initialize_holding(
    pre_data: &ShardData,
    descriptor: &TokenDescriptor,
    is_authorized: bool,
) -> ShardData {
    assert!(
        pre_data.is_empty() || is_authorized,
        "Only Uninitialized or authorized accounts can be initialized"
    );

    ShardData::from(&descriptor.zeroized())
}
