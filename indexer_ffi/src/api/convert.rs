use crate::api::types::BlockOpt;

impl From<Option<sequencer_core::block_settlement_client::Block>> for BlockOpt {
    fn from(value: Option<sequencer_core::block_settlement_client::Block>) -> Self {
        match value {
            None => BlockOpt {
                block: std::ptr::null_mut(),
                is_ok: false,
            },
            Some(block_orig) => BlockOpt {
                block: block_orig.into(),
                is_ok: true,
            },
        }
    }
}
