use common::{
    rpc_primitives::errors::{RpcError, RpcParseError},
    transaction::TransactionMalformationError,
};
use log::debug;

pub struct RpcErr(pub RpcError);

pub type RpcErrInternal = anyhow::Error;

pub trait RpcErrKind: 'static {
    fn into_rpc_err(self) -> RpcError;
}

impl<T: RpcErrKind> From<T> for RpcErr {
    fn from(e: T) -> Self {
        Self(e.into_rpc_err())
    }
}

macro_rules! standard_rpc_err_kind {
    ($type_name:path) => {
        impl RpcErrKind for $type_name {
            fn into_rpc_err(self) -> RpcError {
                self.into()
            }
        }
    };
}
standard_rpc_err_kind!(RpcError);
standard_rpc_err_kind!(RpcParseError);

impl RpcErrKind for serde_json::Error {
    fn into_rpc_err(self) -> RpcError {
        RpcError::serialization_error(&self.to_string())
    }
}

impl RpcErrKind for RpcErrInternal {
    fn into_rpc_err(self) -> RpcError {
        RpcError::new_internal_error(None, &format!("{self:#?}"))
    }
}

impl RpcErrKind for TransactionMalformationError {
    fn into_rpc_err(self) -> RpcError {
        RpcError::invalid_params(Some(serde_json::to_value(self).unwrap()))
    }
}

#[allow(clippy::needless_pass_by_value)]
#[must_use]
pub fn from_rpc_err_into_anyhow_err(rpc_err: RpcError) -> anyhow::Error {
    debug!("Rpc error cast to anyhow error : err {rpc_err:?}");
    anyhow::anyhow!(format!("{rpc_err:#?}"))
}
