//! The messages dashboard: one actor's messages, each the root of a trace of
//! its own, from the traces the sequencer exports. A click on a message
//! selects it, showing the messages it sent and what it did; a click on what a
//! message was sent from selects that one. So clicks go from message to
//! message, either way.

#![expect(
    clippy::non_ascii_literal,
    reason = "titles use `·` intentionally, matching the other dashboards"
)]

use dashboard_gen::{Dashboard, FieldOverride, Panel, Target, Unit, textbox_variable};
use sequencer_service_metrics::traces::{
    ACTOR_ATTRIBUTE, CAUSE_ATTRIBUTE, SENDER_ATTRIBUTE, SEQUENCER_ATTRIBUTE,
};

use super::{
    actors::{ACTOR_VAR, actor_variable, sequencer_variable},
    sequencer::SEQUENCER_VAR,
};

pub const UID: &str = "sequencer-messages";

/// Dashboard variable holding the id of the selected message's trace.
const TRACE_VAR: &str = "trace";

/// Dashboard variable holding a part of a message name, e.g. `ProduceBlock`,
/// which the actor tables keep to the messages named with. Empty, they keep
/// them all.
const MESSAGE_VAR: &str = "message";

/// Tempo's column of the id of the trace a span links to: for a message, the
/// one it was sent from.
const LINKED_TRACE: &str = "link:traceID";

/// [`LINKED_TRACE`] renamed, for data links to reference.
const SENT_FROM_TRACE: &str = "sentFromTrace";

/// Tempo's column of the id of the span's own trace.
const TRACE_ID: &str = "traceIdHidden";

const MESSAGE: &str = "Message";
const SENT_FROM: &str = "Sent from";
const START_TIME: &str = "Start time";

const SENDER: &str = "Sender";
const DURATION: &str = "Duration";

/// The time of day a message started at, to the millisecond: the time range
/// gives the day.
const START_TIME_FORMAT: &str = "time:HH:mm:ss.SSS";

/// Wide enough for a [`START_TIME_FORMAT`] time.
const START_TIME_WIDTH: u32 = 110;

/// Wide enough for a duration such as `117 ms`.
const DURATION_WIDTH: u32 = 90;

/// Wide enough for most `Actor.Message` names, wider than Tempo's 200 pixels,
/// and narrow enough to leave room in a half-width table.
const MESSAGE_WIDTH: u32 = 260;

const SELECTED_DESCRIPTION: &str = "The message selected by a click on it below. A click on what it was sent from selects that one instead.";

const SENT_DESCRIPTION: &str =
    "The messages sent while the selected one was handled. A click on one selects it.";

const TRACE_DESCRIPTION: &str = "The selected message's handler: its spans, with their timings.";

const ON_CLICK_DESCRIPTION: &str =
    "A click on one selects it on the Messages dashboard, with the messages it sent in turn.";

/// The most of an actor's messages [`actor_messages`] lists: all of them over
/// a few hours, even of the busiest actor.
const ALL_LIMIT: u32 = 10_000;

/// The most of an actor's messages [`newest_actor_messages`] lists.
const NEWEST_LIMIT: u32 = 200;

/// Where a message table is.
#[derive(Clone, Copy)]
enum Place {
    /// On this dashboard, under its Message field.
    Here,
    /// On another dashboard, with the same `sequencer` and `actor` variables.
    Elsewhere,
}

impl Place {
    /// The condition an actor table's search joins on to keep to the Message
    /// field's text.
    fn filter(self) -> String {
        match self {
            Self::Here => format!(r#" && name =~ ".*${MESSAGE_VAR}.*""#),
            Self::Elsewhere => String::new(),
        }
    }

    /// This dashboard, with the message whose trace is `trace` selected, e.g.
    /// `${__data.fields.traceIdHidden}`, keeping the Message field's text
    /// when already on it.
    fn select(self, trace: &str) -> String {
        let kept = match self {
            Self::Here => format!("&var-{MESSAGE_VAR}=${{{MESSAGE_VAR}}}"),
            Self::Elsewhere => String::new(),
        };
        format!("{}&var-{TRACE_VAR}={trace}{kept}", url())
    }
}

/// This dashboard, showing the messages of the actor and sequencer selected
/// on the dashboard the link is on, over its time range.
pub fn url() -> String {
    format!(
        "/d/{UID}?var-{SEQUENCER_VAR}=${{{SEQUENCER_VAR}}}&var-{ACTOR_VAR}=${{{ACTOR_VAR}}}&${{__url_time_range}}"
    )
}

/// This dashboard, showing the messages of the actor and sequencer selected
/// on the dashboard the link is on, over `window_ms` milliseconds centered on
/// the moment of the point the link is on.
pub fn around_point(window_ms: u32) -> String {
    format!(
        "/d/{UID}?var-{SEQUENCER_VAR}=${{{SEQUENCER_VAR}}}&var-{ACTOR_VAR}=${{{ACTOR_VAR}}}&time=${{__value.time}}&time.window={window_ms}"
    )
}

/// [`around_point`], only the messages named as the series the point is on,
/// e.g. `ExecutorActor.ProduceBlock`.
pub fn around_point_of_series(window_ms: u32) -> String {
    format!(
        "{}&var-{MESSAGE_VAR}=${{__field.displayName}}",
        around_point(window_ms)
    )
}

/// A search for the messages `traceql` matches, with the columns the
/// message tables show.
fn spans(traceql: &str) -> Target {
    Target::spans(format!(
        "{traceql} | select(span.{SENDER_ATTRIBUTE}, span.{CAUSE_ATTRIBUTE}, {LINKED_TRACE})"
    ))
}

/// A table of the messages `search` finds, newest first, counted, at `place`.
fn messages(title: &str, description: &str, search: Target, place: Place) -> Panel {
    Panel::table(title)
        .description(description)
        .target(search)
        .count_rows()
        .column(START_TIME, START_TIME)
        .column("Trace Name", MESSAGE)
        .column(SENDER_ATTRIBUTE, SENDER)
        .column(CAUSE_ATTRIBUTE, SENT_FROM)
        .column(DURATION, DURATION)
        .column(LINKED_TRACE, SENT_FROM_TRACE)
        // The ones Tempo adds, and the attributes `traceql` matches on.
        .drop_columns(&[
            "Trace Service",
            "Span ID",
            "Name",
            "nestedSetParent",
            ACTOR_ATTRIBUTE,
            SEQUENCER_ATTRIBUTE,
        ])
        .sort_descending(START_TIME)
        .with_override(
            FieldOverride::by_name(START_TIME)
                .unit(Unit::custom(START_TIME_FORMAT))
                .width(START_TIME_WIDTH),
        )
        .with_override(FieldOverride::by_name(DURATION).width(DURATION_WIDTH))
        .with_override(FieldOverride::by_name(MESSAGE).width(MESSAGE_WIDTH).link(
            "Select this message",
            place.select(&format!("${{__data.fields.{TRACE_ID}}}")),
        ))
        .with_override(FieldOverride::by_name(SENT_FROM).link(
            "Select the message it was sent from",
            place.select(&format!("${{__data.fields.{SENT_FROM_TRACE}}}")),
        ))
        .with_override(FieldOverride::by_name(TRACE_ID).hidden())
        .with_override(FieldOverride::by_name(SENT_FROM_TRACE).hidden())
}

/// The spans of the selected sequencer's messages whose `attribute` is the
/// selected actor: [`SENDER_ATTRIBUTE`] for the ones it sent,
/// [`ACTOR_ATTRIBUTE`] for the ones it handled.
pub fn of_actor(attribute: &str) -> String {
    format!("{{ {} }}", actor_condition(attribute))
}

/// [`of_actor`] without its braces, for more conditions to join.
fn actor_condition(attribute: &str) -> String {
    format!(
        r#"span.{SEQUENCER_ATTRIBUTE} = "${SEQUENCER_VAR}" && span.{attribute} = "${ACTOR_VAR}""#
    )
}

/// The messages the selected actor of the selected sequencer sent, and the
/// ones it handled, side by side: all of them over the time range, up to
/// [`ALL_LIMIT`]. For any dashboard with the same `sequencer` and `actor`
/// variables: a click on a message selects it here.
pub fn actor_messages() -> [Panel; 2] {
    let limit = grouped(ALL_LIMIT);
    actor_tables(
        ALL_LIMIT,
        &format!(
            "Only the ones whose name has the Message field's text in it, all of them if it is empty. All of them, up to the newest {limit}, counted under the table. A count of {limit} means there are more: narrow the time range to see the older ones."
        ),
        Place::Here,
    )
}

/// [`actor_messages`], only the newest [`NEWEST_LIMIT`] of each, their
/// headers linking to all of them here: for a dashboard refreshing every few
/// seconds.
pub fn newest_actor_messages() -> [Panel; 2] {
    actor_tables(
        NEWEST_LIMIT,
        &format!(
            "Only the newest {}, counted under the table. The link in the header opens all of them, up to the newest {}, on the Messages dashboard.",
            grouped(NEWEST_LIMIT),
            grouped(ALL_LIMIT),
        ),
        Place::Elsewhere,
    )
    .map(|panel| panel.header_link("All of them", url()))
}

/// The selected actor's messages, sent and handled, at `place`, up to
/// `limit` of each, which their titles name. `how_many` says which of them,
/// in their descriptions.
fn actor_tables(limit: u32, how_many: &str, place: Place) -> [Panel; 2] {
    let search = |attribute: &str| {
        spans(&format!(
            "{{ {}{} }}",
            actor_condition(attribute),
            place.filter()
        ))
        .limit(limit)
    };
    let title = |done: &str| format!("${{actor}} · messages {done}, newest {}", grouped(limit));
    let description = |done: &str| {
        format!(
            "Messages the actor {done} over the time range, newest first. {how_many} {ON_CLICK_DESCRIPTION}"
        )
    };
    [
        // Their sender is the actor.
        messages(
            &title("sent"),
            &description("sent"),
            search(SENDER_ATTRIBUTE),
            place,
        )
        .drop_columns(&[SENDER_ATTRIBUTE]),
        messages(
            &title("handled"),
            &description("handled"),
            search(ACTOR_ATTRIBUTE),
            place,
        ),
    ]
}

/// `number` with its thousands set apart, e.g. `10 000`.
fn grouped(number: u32) -> String {
    let reversed: Vec<char> = number.to_string().chars().rev().collect();
    let mut groups: Vec<String> = reversed
        .chunks(3)
        .map(|group| group.iter().rev().collect())
        .collect();
    groups.reverse();
    groups.join(" ")
}

pub fn dashboard() -> Dashboard {
    let trace = format!("${TRACE_VAR}");
    Dashboard::new("Messages", UID)
        .tag(super::TAG)
        .link_tagged("Dashboards", super::TAG)
        // Fresh rows would shift the ones about to be clicked.
        .refresh("")
        .variable(sequencer_variable())
        .variable(actor_variable())
        .variable(textbox_variable(MESSAGE_VAR, "Message"))
        .variable(textbox_variable(TRACE_VAR, "Selected message's trace"))
        .row(
            5,
            [messages(
                "Selected message",
                SELECTED_DESCRIPTION,
                spans(&format!(
                    r#"{{ trace:id = "{trace}" && nestedSetParent = -1 }}"#
                )),
                Place::Here,
            )],
        )
        .row(
            8,
            [messages(
                "Messages it sent",
                SENT_DESCRIPTION,
                spans(&format!(r#"{{ {LINKED_TRACE} = "{trace}" }}"#)),
                Place::Here,
            )],
        )
        // Folded, as a trace panel with no trace to show fails.
        .folded(
            "What the selected message did",
            12,
            [Panel::trace("What the selected message did")
                .description(TRACE_DESCRIPTION)
                .target(Target::trace(trace))],
        )
        .heading("${actor} · messages")
        .row(12, actor_messages())
}
