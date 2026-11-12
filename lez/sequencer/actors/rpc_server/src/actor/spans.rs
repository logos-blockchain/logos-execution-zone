//! A span around every RPC call, the root of the trace of all it causes.

use jsonrpsee::server::middleware::rpc::{Batch, Notification, Request, RpcServiceT};
use tracing::Instrument as _;

/// Runs each call to the wrapped service in an `rpc` span. Calls in a batch
/// share the batch's.
#[derive(Clone)]
pub struct RpcSpans<S>(pub S);

impl<S: RpcServiceT + Send + Sync + Clone + 'static> RpcServiceT for RpcSpans<S> {
    type BatchResponse = S::BatchResponse;
    type MethodResponse = S::MethodResponse;
    type NotificationResponse = S::NotificationResponse;

    fn call<'request>(
        &self,
        request: Request<'request>,
    ) -> impl Future<Output = Self::MethodResponse> + Send + 'request {
        let span = rpc_span(request.method_name());
        self.0.call(request).instrument(span)
    }

    fn batch<'request>(
        &self,
        requests: Batch<'request>,
    ) -> impl Future<Output = Self::BatchResponse> + Send + 'request {
        self.0.batch(requests).instrument(rpc_span("batch"))
    }

    #[expect(
        clippy::renamed_function_params,
        reason = "The trait's name for it, `n`, says nothing"
    )]
    fn notification<'request>(
        &self,
        notification: Notification<'request>,
    ) -> impl Future<Output = Self::NotificationResponse> + Send + 'request {
        let span = rpc_span(&notification.method);
        self.0.notification(notification).instrument(span)
    }
}

/// A root span, rather than one inside jsonrpsee's span for the connection,
/// which lasts as long as the client keeps it open.
fn rpc_span(method: &str) -> tracing::Span {
    tracing::info_span!(
        parent: None,
        "rpc",
        otel.name = format!("rpc.{method}"),
        rpc.method = method,
    )
}
