use common::{
    rpc_primitives::errors::{RpcError, RpcParseError},
    transaction::TransactionMalformationError,
};

macro_rules! standard_rpc_err_kind {
    ($type_name:path) => {
        impl RpcErrKind for $type_name {
            fn into_rpc_err(self) -> RpcError {
                self.into()
            }
        }
    };
}

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
