use lee_core::account::ActorState;
use token_core::{TokenDefinition, TokenDescriptor, TokenHolding, TokenKind, same_asset};

pub fn check_holding_kind(pre_state: &ActorState, kind: TokenKind) {
    let definition =
        TokenDefinition::try_from(pre_state).expect("Definition account must be valid");

    assert_eq!(
        TokenKind::from_definition(&definition),
        kind,
        "Token Definition does not initialize this Token Holding kind"
    );
}

#[must_use]
pub fn ensure_holding(
    pre_state: &ActorState,
    descriptor: &TokenDescriptor,
    is_authorized: bool,
) -> Option<ActorState> {
    if !pre_state.is_empty() {
        if TokenHolding::try_from(pre_state).is_ok_and(|holding| {
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

    Some(ActorState::from(&descriptor.zeroized()))
}
