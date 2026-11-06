//! The logging setup shared by our binaries: `tracing` events, and `log`
//! records from dependencies, filtered by `RUST_LOG` and written to stderr.
//!
//! `LOG_FORMAT=json` writes one JSON object per line, the event's fields at
//! its top level, for log collectors to parse. Otherwise lines are plain text.

use std::io::IsTerminal as _;

use tracing::Subscriber;
pub use tracing_subscriber::EnvFilter;
use tracing_subscriber::{
    Layer,
    layer::{Filter, SubscriberExt as _},
    registry::LookupSpan,
    util::{SubscriberInitExt as _, TryInitError},
};

/// The environment variable picking the [`Format`].
pub const FORMAT_ENV: &str = "LOG_FORMAT";

/// How log lines are written.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Format {
    /// Human-readable text, colored on a terminal.
    #[default]
    Text,
    /// One JSON object per line.
    Json,
}

impl Format {
    /// The format [`FORMAT_ENV`] names, `json` or anything else for text.
    #[must_use]
    pub fn from_env() -> Self {
        match std::env::var(FORMAT_ENV) {
            Ok(format) if format.eq_ignore_ascii_case("json") => Self::Json,
            _ => Self::Text,
        }
    }
}

/// Installs the global subscriber, filtered by `RUST_LOG`.
///
/// # Panics
/// If a global `tracing` subscriber or `log` logger is already installed.
pub fn init() {
    try_init().expect("Failed to install the logger");
}

/// Installs the global subscriber, filtered by `RUST_LOG`.
pub fn try_init() -> Result<(), TryInitError> {
    try_init_with_filter(EnvFilter::from_default_env())
}

/// Installs the global subscriber, filtered by `filter`.
pub fn try_init_with_filter(filter: EnvFilter) -> Result<(), TryInitError> {
    tracing_subscriber::registry()
        .with(layer(filter))
        .try_init()
}

/// The layer writing the spans and events `filter` lets through, in the
/// [`FORMAT_ENV`] format, for a subscriber composed of more layers than this one.
pub fn layer<S, F>(filter: F) -> impl Layer<S>
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    F: Filter<S> + Send + Sync + 'static,
{
    let layer = tracing_subscriber::fmt::layer().with_writer(std::io::stderr);
    let layer = match Format::from_env() {
        Format::Text => layer.with_ansi(std::io::stderr().is_terminal()).boxed(),
        Format::Json => layer
            .json()
            .flatten_event(true)
            .with_current_span(true)
            .with_span_list(false)
            .boxed(),
    };
    layer.with_filter(filter)
}
