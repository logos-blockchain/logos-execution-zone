use crate::protocol;

impl From<protocol::TransactionOrigin> for sequencer_core::TransactionOrigin {
    fn from(value: protocol::TransactionOrigin) -> Self {
        match value {
            protocol::TransactionOrigin::User => Self::User,
            protocol::TransactionOrigin::Gossip => Self::Gossip,
        }
    }
}

impl From<sequencer_core::fees::FeeStateQuote> for protocol::FeeStateQuote {
    fn from(value: sequencer_core::fees::FeeStateQuote) -> Self {
        Self {
            height: value.height,
            base_fee_exec: value.base_fee_exec,
            base_fee_stor: value.base_fee_stor,
            next_base_fee_exec_floor: value.next_base_fee_exec_floor,
            next_base_fee_exec_ceiling: value.next_base_fee_exec_ceiling,
            next_base_fee_stor_floor: value.next_base_fee_stor_floor,
            next_base_fee_stor_ceiling: value.next_base_fee_stor_ceiling,
            max_gas_exec: value.max_gas_exec,
            max_gas_stor: value.max_gas_stor,
        }
    }
}
