use std::fmt;

use serde_json::{Value, to_value};

#[derive(serde::Serialize)]
pub struct RpcParseError(pub String);

/// This struct may be returned from JSON RPC server in case of error.
///
/// It is expected that that this struct has impls From<_> all other RPC errors
/// like [`RpcBlockError`](crate::types::blocks::RpcBlockError).
#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RpcError {
    #[serde(flatten)]
    pub error_struct: Option<RpcErrorKind>,
    /// Deprecated please use the `error_struct` instead.
    pub code: i64,
    /// Deprecated please use the `error_struct` instead.
    pub message: String,
    /// Deprecated please use the `error_struct` instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq, Eq)]
#[serde(tag = "name", content = "cause", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RpcErrorKind {
    RequestValidationError(RpcRequestValidationErrorKind),
    HandlerError(Value),
    InternalError(Value),
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq, Eq)]
#[serde(tag = "name", content = "info", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RpcRequestValidationErrorKind {
    MethodNotFound { method_name: String },
    ParseError { error_message: String },
}

/// A general Server Error.
#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum ServerError {
    Timeout,
    Closed,
}

impl RpcError {
    /// A generic constructor.
    ///
    /// Mostly for completeness, doesn't do anything but filling in the corresponding fields.
    #[must_use]
    pub const fn new(code: i64, message: String, data: Option<Value>) -> Self {
        Self {
            code,
            message,
            data,
            error_struct: None,
        }
    }

    /// Create an Invalid Param error.
    pub fn invalid_params(data: impl serde::Serialize) -> Self {
        let value = match to_value(data) {
            Ok(value) => value,
            Err(err) => {
                return Self::server_error(Some(format!(
                    "Failed to serialize invalid parameters error: {:?}",
                    err.to_string()
                )));
            }
        };
        Self::new(-32_602, "Invalid params".to_owned(), Some(value))
    }

    /// Create a server error.
    pub fn server_error<E: serde::Serialize>(e: Option<E>) -> Self {
        Self::new(
            -32_000,
            "Server error".to_owned(),
            e.map(|v| to_value(v).expect("Must be representable in JSON")),
        )
    }

    /// Create a parse error.
    #[must_use]
    pub fn parse_error(e: String) -> Self {
        Self {
            code: -32_700,
            message: "Parse error".to_owned(),
            data: Some(Value::String(e.clone())),
            error_struct: Some(RpcErrorKind::RequestValidationError(
                RpcRequestValidationErrorKind::ParseError { error_message: e },
            )),
        }
    }

    #[must_use]
    pub fn serialization_error(e: &str) -> Self {
        Self::new_internal_error(Some(Value::String(e.to_owned())), e)
    }

    /// Helper method to define extract `INTERNAL_ERROR` in separate `RpcErrorKind`
    /// Returns `HANDLER_ERROR` if the error is not internal one.
    #[must_use]
    pub fn new_internal_or_handler_error(error_data: Option<Value>, error_struct: Value) -> Self {
        if error_struct["name"] == "INTERNAL_ERROR" {
            let error_message = match error_struct["info"].get("error_message") {
                Some(Value::String(error_message)) => error_message.as_str(),
                _ => "InternalError happened during serializing InternalError",
            };
            Self::new_internal_error(error_data, error_message)
        } else {
            Self::new_handler_error(error_data, error_struct)
        }
    }

    #[must_use]
    pub fn new_internal_error(error_data: Option<Value>, info: &str) -> Self {
        Self {
            code: -32_000,
            message: "Server error".to_owned(),
            data: error_data,
            error_struct: Some(RpcErrorKind::InternalError(serde_json::json!({
                "name": "INTERNAL_ERROR",
                "info": serde_json::json!({"error_message": info})
            }))),
        }
    }

    fn new_handler_error(error_data: Option<Value>, error_struct: Value) -> Self {
        Self {
            code: -32_000,
            message: "Server error".to_owned(),
            data: error_data,
            error_struct: Some(RpcErrorKind::HandlerError(error_struct)),
        }
    }

    /// Create a method not found error.
    #[must_use]
    pub fn method_not_found(method: String) -> Self {
        Self {
            code: -32_601,
            message: "Method not found".to_owned(),
            data: Some(Value::String(method.clone())),
            error_struct: Some(RpcErrorKind::RequestValidationError(
                RpcRequestValidationErrorKind::MethodNotFound {
                    method_name: method,
                },
            )),
        }
    }
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl From<RpcParseError> for RpcError {
    fn from(parse_error: RpcParseError) -> Self {
        Self::parse_error(parse_error.0)
    }
}

impl From<std::convert::Infallible> for RpcError {
    fn from(_: std::convert::Infallible) -> Self {
        // SAFETY: Infallible error can never be constructed, so this code can never be reached.
        unsafe { core::hint::unreachable_unchecked() }
    }
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => write!(f, "ServerError: Timeout"),
            Self::Closed => write!(f, "ServerError: Closed"),
        }
    }
}

impl From<ServerError> for RpcError {
    fn from(e: ServerError) -> Self {
        let error_data = match to_value(&e) {
            Ok(value) => value,
            Err(_err) => {
                return Self::new_internal_error(None, "Failed to serialize ServerError");
            }
        };
        Self::new_internal_error(Some(error_data), e.to_string().as_str())
    }
}
