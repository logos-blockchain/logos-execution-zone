use lee_core::account::ShardData;
use token_core::{TokenDefinition, TokenDescriptor, TokenHolding, TokenKind, same_asset};

pub fn check_holding_kind(pre_data: &ShardData, kind: TokenKind) {
    let definition = TokenDefinition::try_from(pre_data).expect("Definition account must be valid");

    assert_eq!(
        TokenKind::from_definition(&definition),
        kind,
        "Token Definition does not initialize this Token Holding kind"
    );
}

#[must_use]
pub fn ensure_holding(
    pre_data: &ShardData,
    descriptor: &TokenDescriptor,
    is_authorized: bool,
) -> Option<ShardData> {
    if !pre_data.is_empty() {
        if TokenHolding::try_from(pre_data).is_ok_and(|holding| {
            holding.definition_id() == descriptor.definition_id
                && same_asset(holding.kind(), descriptor.kind)
        }) {
            return None;
        }
        assert!(
            is_authorized,
            "Only Uninitialized or authorized accounts can be initialized"
        );
    }

    Some(ShardData::from(&descriptor.zeroized()))
}
