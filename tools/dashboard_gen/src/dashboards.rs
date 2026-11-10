//! One module per dashboard, each exposing a `dashboard()` builder.

pub mod network;
pub mod sequencer;

/// Tag on every sequencer dashboard, which their top-bar links list.
const TAG: &str = "sequencer";

/// Matchers picking warnings and errors out of the logs, by the `level` label
/// `monitoring/alloy/config.alloy` gives every line.
const WARNINGS_AND_ERRORS: &str = r#"level=~"WARN|ERROR""#;

/// A log stream selector from `matchers`, e.g. `["sequencer=\"$sequencer\""]`.
fn logs(matchers: &[&str]) -> String {
    format!("{{{}}}", matchers.join(", "))
}
