//! The ops HTTP server: `/ping`, `/health` and `/metrics`, on a port apart from the RPC so it can
//! be proxied or firewalled on its own.

use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context as _, Result};
use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use metrics_exporter_prometheus::PrometheusHandle;
use sequencer_service::SequencerHandle;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
struct Ops {
    metrics: PrometheusHandle,
    sequencer: Arc<SequencerHandle>,
}

/// Binds first, so a taken or invalid address fails `start` instead of a background task.
pub async fn bind(address: SocketAddr) -> Result<TcpListener> {
    TcpListener::bind(address)
        .await
        .with_context(|| format!("Failed to bind the ops server to {address}"))
}

/// Serves until `shutdown` is cancelled.
pub async fn serve(
    listener: TcpListener,
    metrics: PrometheusHandle,
    sequencer: Arc<SequencerHandle>,
    shutdown: CancellationToken,
) -> Result<()> {
    let router = Router::new()
        .route("/ping", get(|| async { "pong" }))
        .route("/health", get(health))
        .route("/metrics", get(render_metrics))
        .with_state(Ops { metrics, sequencer });
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown.cancelled_owned())
        .await
        .context("Ops server failed")
}

/// 503 once any of the sequencer's tasks has died. Gossip is not part of it: without gossip the
/// node keeps running on L1 alone.
async fn health(State(ops): State<Ops>) -> (StatusCode, Json<Value>) {
    if ops.sequencer.is_healthy() {
        (StatusCode::OK, Json(json!({ "status": "ok" })))
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "failing" })),
        )
    }
}

async fn render_metrics(State(ops): State<Ops>) -> String {
    ops.metrics.render()
}
