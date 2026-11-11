//! The logging setup shared by our binaries: `tracing` events, and `log`
//! records from dependencies, filtered by `RUST_LOG` and written to stderr.
//!
//! `LOG_FORMAT=json` writes one JSON object per line, for log collectors to
//! parse: the event's fields at its top level, its message before any other,
//! the fields of every span it ran in under `span`, and, with the `otel`
//! feature while traces are exported, its trace and span ids under
//! `openTelemetry`. Otherwise lines are plain text.

use std::io::IsTerminal as _;

use json_subscriber::JsonLayer;
use tracing::{
    Event, Subscriber,
    field::{Field, Visit},
};
pub use tracing_subscriber::EnvFilter;
use tracing_subscriber::{
    Layer,
    fmt::{MakeWriter, time::SystemTime},
    layer::{Filter, SubscriberExt as _},
    registry::LookupSpan,
    util::{SubscriberInitExt as _, TryInitError},
};

/// The event field holding what an event says, e.g. `Block created`.
const MESSAGE: &str = "message";

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

/// An event's fields as JSON values, in the order the event declares them.
#[derive(Default)]
struct EventFields(Vec<(&'static str, serde_json::Value)>);

impl EventFields {
    fn of(event: &Event<'_>) -> Self {
        let mut fields = Self::default();
        event.record(&mut fields);
        fields
    }

    fn take(mut self, name: &str) -> Option<serde_json::Value> {
        let index = self.0.iter().position(|(key, _)| *key == name)?;
        Some(self.0.swap_remove(index).1)
    }

    /// Sets `name` to `value`, the latest value winning for a name given
    /// twice.
    fn insert(&mut self, name: &'static str, value: serde_json::Value) {
        let name = name.strip_prefix("r#").unwrap_or(name);
        match self.0.iter_mut().find(|(key, _)| *key == name) {
            Some((_, old)) => *old = value,
            None => self.0.push((name, value)),
        }
    }
}

impl Visit for EventFields {
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.insert(field.name(), value.into());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.insert(field.name(), value.into());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.insert(field.name(), value.into());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.insert(field.name(), value.into());
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.insert(field.name(), value.into());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.insert(field.name(), format!("{value:?}").into());
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
    let layer = match Format::from_env() {
        Format::Text => tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr)
            .with_ansi(std::io::stderr().is_terminal())
            .boxed(),
        Format::Json => json_layer(std::io::stderr).boxed(),
    };
    layer.with_filter(filter)
}

fn json_layer<S, W>(make_writer: W) -> JsonLayer<S, W>
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    W: for<'writer> MakeWriter<'writer> + Send + Sync + 'static,
{
    let mut layer = JsonLayer::new(make_writer);
    layer
        .with_timer("timestamp", SystemTime)
        .with_level("level")
        .with_target("target")
        // Merged, so a line logged in an inner span keeps the outer spans'
        // fields, e.g. the name of the actor it runs in.
        .with_flattened_span_fields("span");
    #[cfg(feature = "otel")]
    layer.with_opentelemetry_ids(true);
    // Keyed values go first, in key order, so the message comes right after
    // the level; flattened ones follow.
    layer.add_dynamic_field(MESSAGE, |event, _context| {
        EventFields::of(event).take(MESSAGE)
    });
    layer.add_multiple_dynamic_fields(|event, _context, writer| {
        for (name, value) in EventFields::of(event).0 {
            if name != MESSAGE {
                // Fails only for a map with non-string keys, which no field
                // value is.
                drop(writer.write_field(name, value));
            }
        }
    });
    layer
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Clone, Default)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Buffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("buffer lock").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// The shape log collectors parse: Alloy reads `timestamp`, `level` and
    /// `span."actor.name"`.
    #[test]
    fn json_lines_merge_the_fields_of_every_enclosing_span() {
        let buffer = Buffer::default();
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::registry().with(json_layer(move || writer.clone()));

        tracing::subscriber::with_default(subscriber, || {
            let _actor = tracing::info_span!("actor", actor.name = "ExecutorActor").entered();
            let _inner = tracing::info_span!("inner", event = "turn").entered();
            tracing::info!(block_id = 7, "Block created");
            tracing::info!("Started");
        });

        let output = String::from_utf8(buffer.0.lock().expect("buffer lock").clone())
            .expect("JSON is UTF-8");
        assert!(
            output.starts_with(r#"{"level":"INFO","message":"Block created","#),
            "the message right after the level: {output}"
        );
        let (line, only_message) = output.trim().split_once('\n').expect("two lines");
        let line: serde_json::Value = serde_json::from_str(line).expect("a JSON line");
        let only_message: serde_json::Value =
            serde_json::from_str(only_message).expect("a JSON line");
        assert_eq!(only_message["message"], "Started");
        assert_eq!(line["level"], "INFO");
        assert_eq!(line["message"], "Block created");
        assert_eq!(line["block_id"], 7);
        assert_eq!(line["target"], module_path!());
        assert_eq!(line["span"]["actor.name"], "ExecutorActor");
        assert_eq!(line["span"]["event"], "turn");
        assert!(line["timestamp"].is_string());
        assert!(
            line.get("openTelemetry").is_none(),
            "no ids without an exporter"
        );
    }
}
