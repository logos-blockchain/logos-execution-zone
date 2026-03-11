use serde::de::DeserializeOwned;
use serde_json::Value;

use super::errors::RpcParseError;

#[macro_export]
macro_rules! parse_request {
    ($request_name:ty) => {
        impl RpcRequest for $request_name {
            fn parse(value: Option<Value>) -> Result<Self, RpcParseError> {
                parse_params::<Self>(value)
            }
        }
    };
}

pub trait RpcRequest: Sized {
    fn parse(value: Option<Value>) -> Result<Self, RpcParseError>;
}

pub fn parse_params<T: DeserializeOwned>(value: Option<Value>) -> Result<T, RpcParseError> {
    value.map_or_else(
        || Err(RpcParseError("Require at least one parameter".to_owned())),
        |value| {
            serde_json::from_value(value)
                .map_err(|err| RpcParseError(format!("Failed parsing args: {err}")))
        },
    )
}
