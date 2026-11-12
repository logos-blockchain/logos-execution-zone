//! Hands `tracing` events to the `log` logger.
//!
//! `tracing` does that on its own only until a tracing subscriber is installed;
//! [`LogForwarder`] keeps it going once one is, so libp2p, the zone SDK, kameo
//! and the rest stay in the logs. Its `log-always` feature would do the same,
//! but features unify across every crate built alongside the sequencer, and it
//! would double the logs of any that also feed `log` back into `tracing`.

use std::fmt::{self, Write as _};

use tracing::{
    Event, Level, Metadata, Subscriber,
    field::{Field, Visit},
};
use tracing_subscriber::{Layer, filter::FilterFn, layer::Context, registry::LookupSpan};

/// Hands every event the `log` logger takes to it, its fields written as
/// `tracing` would: the message, then ` name=value` for each other field.
pub struct LogForwarder;

/// An event's fields, in the form `tracing`'s own `log` records take.
#[derive(Default)]
struct Message(String);

impl<S: Subscriber> Layer<S> for LogForwarder {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let metadata = event.metadata();
        let mut message = Message::default();
        event.record(&mut message);
        log::logger().log(
            &log::Record::builder()
                .level(log_level(*metadata.level()))
                .target(metadata.target())
                .module_path(metadata.module_path())
                .file(metadata.file())
                .line(metadata.line())
                .args(format_args!("{}", message.0))
                .build(),
        );
    }
}

impl Visit for Message {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.record_debug(field, &format_args!("{value}"));
        } else {
            self.record_debug(field, &value);
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        let _infallible = if self.0.is_empty() && field.name() == "message" {
            write!(self.0, "{value:?}")
        } else if self.0.is_empty() {
            write!(self.0, "{}={value:?}", field.name())
        } else {
            write!(self.0, " {}={value:?}", field.name())
        };
    }
}

impl LogForwarder {
    /// The forwarder, taking only the events the `log` logger would print.
    pub fn filtered<S: Subscriber + for<'lookup> LookupSpan<'lookup>>() -> impl Layer<S> {
        Self.with_filter(FilterFn::new(|metadata: &Metadata<'_>| {
            metadata.is_event()
                && log::logger().enabled(
                    &log::Metadata::builder()
                        .level(log_level(*metadata.level()))
                        .target(metadata.target())
                        .build(),
                )
        }))
    }
}

const fn log_level(level: Level) -> log::Level {
    match level {
        Level::ERROR => log::Level::Error,
        Level::WARN => log::Level::Warn,
        Level::INFO => log::Level::Info,
        Level::DEBUG => log::Level::Debug,
        _ => log::Level::Trace,
    }
}
