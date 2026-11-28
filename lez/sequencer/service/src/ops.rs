//! The ops HTTP server: `/ping`, `/health` and `/metrics`, on a port apart from the RPC so it can
//! be proxied or firewalled on its own.

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex, OnceLock, Weak},
    time::Duration,
};

use anyhow::{Context as _, Result};
use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use sequencer_core::Ed25519PublicKey;
use serde_json::{Value, json};
use tokio::{net::TcpListener, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::error;

use crate::SequencerHandle;

/// The ops server of a running sequencer, see [`OpsServer::start`].
pub struct OpsServer {
    server: JoinHandle<Result<()>>,
    upkeep: JoinHandle<()>,
    sequencer: Arc<OnceLock<Weak<SequencerHandle>>>,
    shutdown: CancellationToken,
}

impl OpsServer {
    /// Serves the ops server on the config's `metrics_listen_address`, or nothing when it is unset.
    ///
    /// Start it before the sequencer, so probes and metrics answer while startup waits on Bedrock,
    /// and hand it the sequencer with [`Self::set_sequencer`] once that is up.
    pub async fn start(
        address: Option<SocketAddr>,
        public_key: &Ed25519PublicKey,
    ) -> Result<Option<Self>> {
        let Some(address) = address else {
            return Ok(None);
        };
        let listener = bind(address).await?;
        let metrics = install_prometheus_recorder(public_key)?;
        // Without the exporter's own listener, draining histograms is ours to schedule.
        let upkeep_handle = metrics.clone();
        let upkeep = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            loop {
                interval.tick().await;
                upkeep_handle.run_upkeep();
            }
        });
        let sequencer = Arc::new(OnceLock::new());
        let shutdown = CancellationToken::new();
        let server = tokio::spawn(serve(
            listener,
            metrics,
            Arc::clone(&sequencer),
            shutdown.clone(),
        ));
        Ok(Some(Self {
            server,
            upkeep,
            sequencer,
            shutdown,
        }))
    }

    /// Turns `/health` from starting to the sequencer's own health.
    ///
    /// Only a [`Weak`] is kept, so the ops server never owns the sequencer: its owner can shut the
    /// handle down whenever, and `/health` then reports stopping.
    pub fn set_sequencer(&self, sequencer: &Arc<SequencerHandle>) {
        self.sequencer.get_or_init(|| Arc::downgrade(sequencer));
    }

    /// Stops serving.
    pub async fn stop(self) {
        self.shutdown.cancel();
        match self.server.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => error!(error = format_args!("{err:#}"), "Ops server failed"),
            Err(err) => error!(error = %err, "Ops server panicked"),
        }
        self.upkeep.abort();
    }
}

#[derive(Clone)]
struct Ops {
    metrics: PrometheusHandle,
    sequencer: Arc<OnceLock<Weak<SequencerHandle>>>,
}

/// Binds first, so a taken or invalid address fails `start` instead of a background task.
async fn bind(address: SocketAddr) -> Result<TcpListener> {
    TcpListener::bind(address)
        .await
        .with_context(|| format!("Failed to bind the ops server to {address}"))
}

/// Serves until `shutdown` is cancelled. Starts before the sequencer does, so `/ping` and
/// `/metrics` answer during startup; `/health` is 503 until `sequencer` is set.
async fn serve(
    listener: TcpListener,
    metrics: PrometheusHandle,
    sequencer: Arc<OnceLock<Weak<SequencerHandle>>>,
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

/// 503 while starting, once any of the sequencer's tasks has died, and once its handle is gone.
/// Gossip is not part of it: without gossip the node keeps running on L1 alone.
async fn health(State(ops): State<Ops>) -> (StatusCode, Json<Value>) {
    let (code, status) = match ops.sequencer.get().map(Weak::upgrade) {
        None => (StatusCode::SERVICE_UNAVAILABLE, "starting"),
        Some(None) => (StatusCode::SERVICE_UNAVAILABLE, "stopping"),
        Some(Some(sequencer)) if sequencer.is_healthy() => (StatusCode::OK, "ok"),
        Some(Some(_)) => (StatusCode::SERVICE_UNAVAILABLE, "failing"),
    };
    (code, Json(json!({ "status": status })))
}

async fn render_metrics(State(ops): State<Ops>) -> String {
    ops.metrics.render()
}

/// Installs the recorder, whose metrics the ops server renders. Every series is
/// labelled with `public_key`, in hex, so sequencers stay apart wherever they
/// are scraped.
///
/// The recorder is process-global, so a later start in the same process, as an
/// embedder restarting the sequencer does, reuses the first one and its label.
fn install_prometheus_recorder(public_key: &Ed25519PublicKey) -> Result<PrometheusHandle> {
    static RECORDER: Mutex<Option<PrometheusHandle>> = Mutex::new(None);

    let mut recorder = RECORDER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(handle) = recorder.as_ref() {
        return Ok(handle.clone());
    }
    let handle = prometheus_builder(hex::encode(public_key.as_bytes()))?
        .install_recorder()
        .context("Failed to install Prometheus recorder")?;
    *recorder = Some(handle.clone());
    Ok(handle)
}

/// The exporter's naming, buckets and `public_key` label.
pub fn prometheus_builder(public_key: String) -> Result<PrometheusBuilder> {
    /// Ladder for `*_seconds` histograms, densest across the 1-100 ms band where
    /// block production and transaction application actually land.
    const LATENCY_BUCKETS: &[f64] = &[
        0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    ];

    /// Fallback ladder for histograms that count things rather than measure time.
    const COUNT_BUCKETS: &[f64] = &[1.0, 2.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0];

    PrometheusBuilder::new()
        .with_recommended_naming(true)
        .add_global_label(
            sequencer_service_metrics::names::SEQUENCER_LABEL,
            public_key,
        )
        .set_buckets(COUNT_BUCKETS)
        .context("Failed to set default histogram buckets")?
        .set_buckets_for_metric(Matcher::Suffix("_seconds".to_owned()), LATENCY_BUCKETS)
        .context("Failed to set latency histogram buckets")
}
