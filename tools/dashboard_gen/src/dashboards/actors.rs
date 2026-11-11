//! The actors dashboard: mailbox traffic, handling time and lifecycle of one
//! sequencer's actors, side by side and then of one actor picked from a
//! dropdown.
//!
//! Actors go by their type name alone, e.g. `ExecutorActor`: kameo labels
//! series with the full type, module path and generic arguments included.

#![expect(
    clippy::non_ascii_literal,
    reason = "titles and legends use `·` intentionally, matching the other dashboards"
)]

use dashboard_gen::{
    Color, Dashboard, FieldOverride, Panel, Selector, StackingMode, Target, Thresholds, Unit,
    Variable, explore_logs_url, label_values_variable, percentile_legend, percentile_variable,
    selected_percentile_expr, selected_quantile,
};
use sequencer_service_metrics::{
    names::{
        ACTOR_MAILBOX_CAPACITY, ACTOR_MESSAGE_HANDLING_TIME, ACTOR_NAME_LABEL, ACTOR_START_TIME,
        ACTOR_STATE, ActorState, KAMEO_LIFECYCLE_RECEIVED_TOTAL, KAMEO_LINK_DIED_RECEIVED_TOTAL,
        KAMEO_MESSAGES_RECEIVED_TOTAL, KAMEO_MESSAGES_SENT_TOTAL, MESSAGE_NAME_LABEL, NO_SENDER,
        SENDER_LABEL, SEQUENCER_LABEL,
    },
    traces::{ACTOR_ATTRIBUTE, SENDER_ATTRIBUTE},
};

use super::{messages, sequencer::SEQUENCER_VAR};

pub const UID: &str = "sequencer-actors";

const PERCENTILES: &[u32] = &[50, 90, 95, 99];
const DEFAULT_PERCENTILE: u32 = 95;

/// Dashboard variable holding the type name of the actor the detail panels show.
pub const ACTOR_VAR: &str = "actor";

/// Label the overview queries put each actor's type name in.
const ACTOR_LABEL: &str = "actor";

/// The module path ahead of the type name in [`ACTOR_NAME_LABEL`], e.g.
/// `sequencer_storage_actor::actor::`. Derived actors have none.
const MODULE_PATH: &str = "(?:[a-z0-9_]+::)*";

/// An actor's type name, without its generic arguments.
const TYPE_NAME: &str = "[A-Za-z0-9_]+";

const LEGEND_PER_ACTOR: &str = "{{actor}}";

/// Label the per-message queries put each message's type name in.
const MESSAGE_LABEL: &str = "message";

const LEGEND_PER_MESSAGE: &str = "{{message}}";

const AVERAGE_LEGEND_SUFFIX: &str = " · avg";

const BACKLOG_DESCRIPTION: &str = "Messages sent to the actor and not yet taken off its mailbox.";

const FILL_DESCRIPTION: &str = "Backlog as a share of the mailbox capacity: at 100%, senders wait. An unbounded mailbox never fills, so it has no fill.";

const HANDLING_TIME_DESCRIPTION: &str = "From taking a message off the mailbox to its handler returning, awaits included. A handler that replies from a background task counts only until it hands the work off.";

const TIME_SPENT_DESCRIPTION: &str = "Handling time summed per message: what the actor spends its time on. A frequent fast message can outweigh a rare slow one.";

const HANDLED_DESCRIPTION: &str = "Messages the actor finished handling. Whether it keeps up with the ones sent shows in the backlog.";

const BUSY_DESCRIPTION: &str = "Share of the time the actor spends handling messages. Near 100%, it cannot keep up and its backlog grows.";

const RESTARTS_DESCRIPTION: &str =
    "Starts after the first, over the time range: a restart of the sequencer or by a supervisor.";

/// What a `TraceQL` metrics query counts each point over. Over a few seconds,
/// spans jump about; over half a minute, they read like the metrics' rates.
const TRACES_STEP: &str = "30s";

/// The time around a point of a `TraceQL` metrics query that a click on it
/// shows the messages of: twice [`TRACES_STEP`], covering the step on either
/// side of the point's timestamp.
const TRACES_WINDOW_MS: u32 = 60_000;

const FROM_TRACES_DESCRIPTION: &str = "Read from the traces, one span per message: exact rather than from histogram buckets. The points are exemplars, single messages; a click on one offers its trace in Explore. A click on a line offers the messages around that moment on the Messages dashboard.";

/// The value of the first label in a `TraceQL` metrics series name, e.g.
/// `ProduceBlock` of `{name="ProduceBlock", p=0.95}`.
const SERIES_LABEL_VALUE: &str = r#"^\{[^=]+="?([^",}]*)"?.*\}$"#;

const LIFECYCLE_DESCRIPTION: &str = "Running, stopped, restarting by its supervisor, or failed by a panic or error; empty while the actor does not exist, e.g. the sequencer is down. A state shorter than a scrape may not show; restarts are counted under Restarts.";

/// `metric`'s series from every actor of the selected sequencer.
fn all_actors(metric: &str) -> Selector {
    Selector::new(metric).label_eq(SEQUENCER_LABEL, format!("${SEQUENCER_VAR}"))
}

/// `metric`'s series from the selected actor only.
fn actor(metric: &str) -> Selector {
    all_actors(metric).label_matches(
        ACTOR_NAME_LABEL,
        format!("{MODULE_PATH}${ACTOR_VAR}(?:<.*)?"),
    )
}

/// `expr`'s series with the type name in their `from` label put in `into`.
/// A name with no module path, e.g. a [`SENDER_LABEL`] of `rpc`, stays as is.
fn type_name(expr: &str, into: &str, from: &str) -> String {
    format!(r#"label_replace({expr}, "{into}", "$1", "{from}", "{MODULE_PATH}({TYPE_NAME}).*")"#)
}

/// `expr`'s series with their actor's type name in [`ACTOR_LABEL`].
fn short_names(expr: &str) -> String {
    type_name(expr, ACTOR_LABEL, ACTOR_NAME_LABEL)
}

/// `expr`'s series with their message's type name in [`MESSAGE_LABEL`].
fn short_message_names(expr: &str) -> String {
    type_name(expr, MESSAGE_LABEL, MESSAGE_NAME_LABEL)
}

/// Messages handled per second over the time range, by every actor.
fn handled_per_second() -> String {
    format!("rate({}[$__range])", handled_messages(all_actors))
}

/// The [`Panel::node_graph`] nodes: each actor, at the messages it handled per
/// second over the time range, and each sender that is no actor, e.g. `rpc`,
/// at zero, so that its edges have a start. A node's title is its id.
fn flow_nodes() -> String {
    let rate = handled_per_second();
    format!(
        r#"label_replace(sum by (id) ({actors}) or (sum by (id) ({senders}) > 0) * 0, "title", "$1", "id", "(.*)")"#,
        actors = type_name(&rate, "id", ACTOR_NAME_LABEL),
        senders = type_name(&rate, "id", SENDER_LABEL),
    )
}

/// The [`Panel::node_graph`] edges: from each sender to each actor it sent
/// messages to over the time range, at how many per second.
fn flow_edges() -> String {
    let rate = handled_per_second();
    let ends = type_name(
        &type_name(&rate, "source", SENDER_LABEL),
        "target",
        ACTOR_NAME_LABEL,
    );
    format!(r#"label_join(sum by (source, target) ({ends}) > 0, "id", "->", "source", "target")"#)
}

/// `expr` summed down to one series per message, its type name in
/// [`MESSAGE_LABEL`].
fn per_message(expr: &str) -> String {
    short_message_names(&format!("sum by ({MESSAGE_NAME_LABEL}) ({expr})"))
}

/// The selected actor's handling time per message at the selected
/// percentile, over `window`. Messages it did not handle in the window are
/// left out: `>= 0` drops their `NaN`.
fn handling_time_per_message(window: &str) -> String {
    short_message_names(&format!(
        "{} >= 0",
        selected_percentile_expr(
            &actor(ACTOR_MESSAGE_HANDLING_TIME),
            &[MESSAGE_NAME_LABEL],
            window,
        )
    ))
}

/// The selected actor's average handling time per message, over `window`.
/// Messages it did not handle in the window are left out.
fn average_handling_time_per_message(window: &str) -> String {
    let rate =
        |metric: Selector| format!("sum by ({MESSAGE_NAME_LABEL}) (rate({metric}[{window}]))");
    short_message_names(&format!(
        "{seconds} / ({handled} > 0)",
        seconds = rate(handling_seconds(actor)),
        handled = rate(handled_messages(actor)),
    ))
}

/// `expr` summed down to one series per actor, its type name in [`ACTOR_LABEL`].
fn per_actor(expr: &str) -> String {
    aggregated_per_actor("sum", expr)
}

/// `expr` reduced to one series per actor by `aggregation`, e.g. `max`, its
/// type name in [`ACTOR_LABEL`].
fn aggregated_per_actor(aggregation: &str, expr: &str) -> String {
    short_names(&format!("{aggregation} by ({ACTOR_NAME_LABEL}) ({expr})"))
}

/// Messages queued and not yet taken, per actor. The one being handled is
/// already taken.
fn backlog_per_actor() -> String {
    format!(
        "{sent} - {received}",
        sent = per_actor(&all_actors(KAMEO_MESSAGES_SENT_TOTAL).to_string()),
        received = per_actor(&all_actors(KAMEO_MESSAGES_RECEIVED_TOTAL).to_string()),
    )
}

/// Each bounded mailbox's backlog as a percentage of its capacity.
fn fill_per_actor() -> String {
    format!(
        "100 * ({backlog}) / ({capacity} < +Inf)",
        backlog = backlog_per_actor(),
        capacity = per_actor(&all_actors(ACTOR_MAILBOX_CAPACITY).to_string()),
    )
}

/// The selected actor's messages queued and not yet taken.
fn backlog() -> String {
    format!(
        "sum({sent}) - sum({received})",
        sent = actor(KAMEO_MESSAGES_SENT_TOTAL),
        received = actor(KAMEO_MESSAGES_RECEIVED_TOTAL),
    )
}

/// The selected actor's mailbox capacity, `+Inf` if unbounded.
fn capacity() -> String {
    format!("sum({})", actor(ACTOR_MAILBOX_CAPACITY))
}

/// The handling time histogram's running total of seconds spent.
fn handling_seconds(select: fn(&str) -> Selector) -> Selector {
    select(&format!("{ACTOR_MESSAGE_HANDLING_TIME}_sum"))
}

/// The handling time histogram's running count of messages handled.
fn handled_messages(select: fn(&str) -> Selector) -> Selector {
    select(&format!("{ACTOR_MESSAGE_HANDLING_TIME}_count"))
}

fn fill_thresholds() -> Thresholds {
    Thresholds::base("green")
        .step(50.0, "orange")
        .step(90.0, "red")
}

/// A panel showing [`ACTOR_STATE`], its values named and colored.
fn lifecycle(panel: Panel) -> Panel {
    ActorState::ALL
        .into_iter()
        .fold(panel, |panel, state| {
            let (text, color) = match state {
                ActorState::Stopped => ("stopped", "text"),
                ActorState::Running => ("running", "green"),
                ActorState::Restarting => ("restarting", "orange"),
                ActorState::Failed => ("failed", "red"),
            };
            panel.value_mapping(u8::from(state).to_string(), text, color)
        })
        .description(LIFECYCLE_DESCRIPTION)
}

/// A `TraceQL` metrics query, counting at [`TRACES_STEP`].
fn traces(traceql: String) -> Target {
    Target::trace_metrics(traceql).step(TRACES_STEP)
}

/// A panel of a `TraceQL` metrics query, its series named by the value they
/// are grouped by. A click on a point opens the actor's messages around it,
/// only the ones named as its series if `by_message`.
fn from_traces(panel: Panel, by_message: bool) -> Panel {
    let (title, url) = if by_message {
        (
            "These messages around this moment",
            messages::around_point_of_series(TRACES_WINDOW_MS),
        )
    } else {
        (
            "The messages around this moment",
            messages::around_point(TRACES_WINDOW_MS),
        )
    };
    panel
        .width(8)
        .min(0.0)
        .color(Color::palette_classic())
        .rename_series(SERIES_LABEL_VALUE, "$1")
        .link(title, url)
}

/// A panel with one series per actor; a click shows that actor below.
fn per_actor_panel(panel: Panel) -> Panel {
    panel.link(
        "Show this actor",
        format!(
            "/d/{UID}?var-{SEQUENCER_VAR}=${{{SEQUENCER_VAR}}}&var-{ACTOR_VAR}=${{__field.labels.{ACTOR_LABEL}}}&${{__url_time_range}}"
        ),
    )
}

/// The dropdown of the sequencers running actors.
pub fn sequencer_variable() -> Variable {
    label_values_variable(
        SEQUENCER_VAR,
        "Sequencer",
        KAMEO_MESSAGES_RECEIVED_TOTAL,
        SEQUENCER_LABEL,
    )
}

/// The dropdown of the selected sequencer's actors, by type name.
pub fn actor_variable() -> Variable {
    label_values_variable(
        ACTOR_VAR,
        "Actor",
        &all_actors(KAMEO_MESSAGES_RECEIVED_TOTAL).to_string(),
        ACTOR_NAME_LABEL,
    )
    .regex(format!("/^{MODULE_PATH}({TYPE_NAME})/"))
}

pub fn dashboard() -> Dashboard {
    Dashboard::new("Actors", UID)
        .tag(super::TAG)
        .link_tagged("Dashboards", super::TAG)
        .variable(sequencer_variable())
        .variable(actor_variable())
        .variable(percentile_variable(PERCENTILES, DEFAULT_PERCENTILE))
        .row(
            8,
            [
                per_actor_panel(Panel::bar_gauge("All actors · messages handled over the time range"))
                    .width(6)
                    .decimals(0)
                    .min(0.0)
                    .color(Color::fixed("blue"))
                    .target(
                        Target::new(format!(
                            "sort_desc({})",
                            per_actor(&format!(
                                "increase({}[$__range])",
                                all_actors(KAMEO_MESSAGES_RECEIVED_TOTAL)
                            ))
                        ))
                        .legend(LEGEND_PER_ACTOR)
                        .instant(),
                    ),
                per_actor_panel(Panel::bar_gauge("All actors · handling time over the time range"))
                    .description(format!("At the percentile picked above. {HANDLING_TIME_DESCRIPTION}"))
                    .width(6)
                    .unit(Unit::Seconds)
                    .min(0.0)
                    .color(Color::fixed("purple"))
                    .target(
                        Target::new(format!(
                            "sort_desc({})",
                            short_names(&selected_percentile_expr(
                                &all_actors(ACTOR_MESSAGE_HANDLING_TIME),
                                &[ACTOR_NAME_LABEL],
                                "$__range",
                            ))
                        ))
                        .legend(LEGEND_PER_ACTOR)
                        .instant(),
                    ),
                per_actor_panel(Panel::bar_gauge("All actors · fullest mailbox over the time range"))
                    .description(FILL_DESCRIPTION)
                    .width(6)
                    .unit(Unit::Percent)
                    .decimals(0)
                    .min(0.0)
                    .max(100.0)
                    .thresholds(fill_thresholds())
                    .target(
                        Target::new(format!(
                            "sort_desc(max_over_time(({})[$__range:]))",
                            fill_per_actor()
                        ))
                        .legend(LEGEND_PER_ACTOR)
                        .instant(),
                    ),
                per_actor_panel(Panel::bar_gauge("All actors · restarts over the time range"))
                    .description(RESTARTS_DESCRIPTION)
                    .width(6)
                    .decimals(0)
                    .min(0.0)
                    .thresholds(Thresholds::base("green").step(1.0, "orange"))
                    .target(
                        Target::new(format!(
                            "sort_desc({})",
                            per_actor(&format!(
                                "changes({}[$__range])",
                                all_actors(ACTOR_START_TIME)
                            ))
                        ))
                        .legend(LEGEND_PER_ACTOR)
                        .instant(),
                    ),
            ],
        )
        .row(
            14,
            [Panel::node_graph("All actors · who sends messages to whom over the time range")
                .description(format!("An arrow from what sent messages to the actor that handled them, at messages per second; a circle per actor, at all it handled. A sender is the actor whose code sent the message, else the span it was sent in, e.g. `rpc` for an RPC call; `{NO_SENDER}` outside any span, e.g. the scheduler's timer."))
                .width(24)
                .unit(Unit::custom("msg/s"))
                .decimals(2)
                .target(Target::new(flow_nodes()).table("nodes"))
                .target(Target::new(flow_edges()).table("edges"))],
        )
        .row(
            8,
            [lifecycle(per_actor_panel(Panel::state_timeline("All actors · lifecycle")))
                .width(24)
                .target(
                    Target::new(aggregated_per_actor("max", &all_actors(ACTOR_STATE).to_string()))
                        .legend(LEGEND_PER_ACTOR),
                )],
        )
        .row(
            9,
            [
                per_actor_panel(Panel::timeseries("All actors · messages handled per second"))
                    .width(8)
                    .min(0.0)
                    .color(Color::palette_classic())
                    .target(
                        Target::new(per_actor(&format!(
                            "rate({}[$__rate_interval])",
                            all_actors(KAMEO_MESSAGES_RECEIVED_TOTAL)
                        )))
                        .legend(LEGEND_PER_ACTOR),
                    ),
                per_actor_panel(Panel::timeseries("All actors · mailbox backlog"))
                    .description(BACKLOG_DESCRIPTION)
                    .width(8)
                    .min(0.0)
                    .color(Color::palette_classic())
                    .target(Target::new(backlog_per_actor()).legend(LEGEND_PER_ACTOR)),
                per_actor_panel(Panel::timeseries("All actors · busy"))
                    .description(BUSY_DESCRIPTION)
                    .width(8)
                    .unit(Unit::Percent)
                    .min(0.0)
                    .color(Color::palette_classic())
                    .target(
                        Target::new(format!(
                            "100 * {}",
                            per_actor(&format!(
                                "rate({}[$__rate_interval])",
                                handling_seconds(all_actors)
                            ))
                        ))
                        .legend(LEGEND_PER_ACTOR),
                    ),
            ],
        )
        .row(
            5,
            [
                Panel::stat("${actor} · messages handled since startup")
                    .width(4)
                    .decimals(0)
                    .color(Color::fixed("blue"))
                    .target(
                        Target::new(format!("sum({})", actor(KAMEO_MESSAGES_RECEIVED_TOTAL)))
                            .legend("handled"),
                    ),
                Panel::stat("${actor} · messages handled per second")
                    .width(4)
                    .decimals(2)
                    .color(Color::fixed("green"))
                    .target(
                        Target::new(format!(
                            "sum(rate({}[$__rate_interval]))",
                            actor(KAMEO_MESSAGES_RECEIVED_TOTAL)
                        ))
                        .legend("handled/s"),
                    ),
                Panel::stat("${actor} · backlog")
                    .description(BACKLOG_DESCRIPTION)
                    .width(4)
                    .decimals(0)
                    .color(Color::fixed("orange"))
                    .target(Target::new(backlog()).legend("queued")),
                Panel::stat("${actor} · mailbox capacity")
                    .description("Messages the mailbox holds before senders wait, as read off the mailbox at startup.")
                    .width(4)
                    .decimals(0)
                    .color(Color::fixed("text"))
                    // Grafana matches mappings on the value's JavaScript string.
                    .value_mapping("Infinity", "unbounded", "text")
                    .target(Target::new(capacity()).legend("capacity")),
                Panel::stat("${actor} · busy")
                    .description(BUSY_DESCRIPTION)
                    .width(4)
                    .unit(Unit::Percent)
                    .decimals(1)
                    .thresholds(fill_thresholds())
                    .target(
                        Target::new(format!(
                            "100 * sum(rate({}[$__rate_interval]))",
                            handling_seconds(actor)
                        ))
                        .legend("busy"),
                    ),
                Panel::stat("${actor} · restarts")
                    .description(RESTARTS_DESCRIPTION)
                    .width(4)
                    .decimals(0)
                    .thresholds(Thresholds::base("green").step(1.0, "orange"))
                    .target(
                        Target::new(format!("sum(changes({}[$__range]))", actor(ACTOR_START_TIME)))
                            .legend("restarts"),
                    ),
            ],
        )
        .row(
            8,
            [
                Panel::gauge("${actor} · mailbox fill")
                    .description(FILL_DESCRIPTION)
                    .width(6)
                    .unit(Unit::Percent)
                    .decimals(0)
                    .min(0.0)
                    .max(100.0)
                    .thresholds(fill_thresholds())
                    .target(
                        Target::new(format!(
                            "100 * ({backlog}) / ({capacity} < +Inf)",
                            backlog = backlog(),
                            capacity = capacity(),
                        ))
                        .legend("fill"),
                    ),
                Panel::timeseries("${actor} · mailbox backlog vs capacity")
                    .description(BACKLOG_DESCRIPTION)
                    .width(18)
                    .min(0.0)
                    .target(Target::new(backlog()).legend("queued"))
                    .target(Target::new(format!("{} < +Inf", capacity())).legend("capacity"))
                    .with_override(FieldOverride::by_name("queued").color(Color::fixed("orange")))
                    .with_override(
                        FieldOverride::by_name("capacity")
                            .dashed_line()
                            .color(Color::fixed("red")),
                    ),
            ],
        )
        .row(
            8,
            [
                Panel::bar_gauge("${actor} · time spent per message over the time range")
                    .description(TIME_SPENT_DESCRIPTION)
                    .width(6)
                    .unit(Unit::Seconds)
                    .min(0.0)
                    .color(Color::fixed("purple"))
                    .target(
                        Target::new(format!(
                            "sort_desc({} > 0)",
                            per_message(&format!("increase({}[$__range])", handling_seconds(actor)))
                        ))
                        .legend(LEGEND_PER_MESSAGE)
                        .instant(),
                    ),
                Panel::bar_gauge("${actor} · messages handled over the time range")
                    .description(HANDLED_DESCRIPTION)
                    .header_link("Each message, with what it sent", super::messages::url())
                    .width(6)
                    .decimals(0)
                    .min(0.0)
                    .color(Color::fixed("blue"))
                    .target(
                        Target::new(format!(
                            "sort_desc({} > 0)",
                            per_message(&format!("increase({}[$__range])", handled_messages(actor)))
                        ))
                        .legend(LEGEND_PER_MESSAGE)
                        .instant(),
                    ),
                Panel::bar_gauge(format!("${{actor}} · {} handling time per message over the time range", percentile_legend()))
                    .description(format!("At the percentile picked above. {HANDLING_TIME_DESCRIPTION}"))
                    .width(6)
                    .unit(Unit::Seconds)
                    .min(0.0)
                    .color(Color::fixed("purple"))
                    .target(
                        Target::new(format!("sort_desc({})", handling_time_per_message("$__range")))
                            .legend(LEGEND_PER_MESSAGE)
                            .instant(),
                    ),
                Panel::bar_gauge("${actor} · average handling time per message over the time range")
                    .description(HANDLING_TIME_DESCRIPTION)
                    .width(6)
                    .unit(Unit::Seconds)
                    .min(0.0)
                    .color(Color::fixed("purple"))
                    .target(
                        Target::new(format!(
                            "sort_desc({})",
                            average_handling_time_per_message("$__range")
                        ))
                        .legend(LEGEND_PER_MESSAGE)
                        .instant(),
                    ),
            ],
        )
        .row(
            9,
            [
                Panel::timeseries("${actor} · messages handled per second")
                    .description(format!("{HANDLED_DESCRIPTION} Stacked, the messages add up to all it handles."))
                    .width(8)
                    .min(0.0)
                    .color(Color::palette_classic())
                    .stacking(StackingMode::Normal)
                    .target(
                        Target::new(per_message(&format!(
                            "rate({}[$__rate_interval])",
                            handled_messages(actor)
                        )))
                        .legend(LEGEND_PER_MESSAGE),
                    ),
                Panel::timeseries("${actor} · handling time per message")
                    .description(format!("Solid at the percentile picked above, dashed on average. {HANDLING_TIME_DESCRIPTION}"))
                    .width(8)
                    .unit(Unit::Seconds)
                    .min(0.0)
                    .color(Color::palette_classic())
                    .target(
                        Target::new(handling_time_per_message("$__rate_interval"))
                            .legend(format!("{LEGEND_PER_MESSAGE} · {}", percentile_legend())),
                    )
                    .target(
                        Target::new(average_handling_time_per_message("$__rate_interval"))
                            .legend(format!("{LEGEND_PER_MESSAGE}{AVERAGE_LEGEND_SUFFIX}")),
                    )
                    .with_override(
                        FieldOverride::by_regex(format!("/{AVERAGE_LEGEND_SUFFIX}$/")).dashed_line(),
                    ),
                Panel::timeseries("${actor} · busy per message")
                    .description(format!("{TIME_SPENT_DESCRIPTION} Stacked, the messages add up to the actor's busy. {BUSY_DESCRIPTION}"))
                    .width(8)
                    .unit(Unit::Percent)
                    .min(0.0)
                    .color(Color::palette_classic())
                    .stacking(StackingMode::Normal)
                    .target(
                        Target::new(format!(
                            "100 * {}",
                            per_message(&format!(
                                "rate({}[$__rate_interval])",
                                handling_seconds(actor)
                            ))
                        ))
                        .legend(LEGEND_PER_MESSAGE),
                    ),
            ],
        )
        .row(10, messages::newest_actor_messages())
        .row(
            7,
            [
                lifecycle(Panel::state_timeline("${actor} · lifecycle"))
                    .width(12)
                    .target(Target::new(format!("max({})", actor(ACTOR_STATE))).legend("${actor}")),
                Panel::timeseries("${actor} · lifecycle and link signals since startup")
                    .description("Signals the actor took off its mailbox, as running totals: starts, stops and restarts, and deaths of actors linked to it, as under supervision.")
                    .width(12)
                    .min(0.0)
                    .target(
                        Target::new(format!("sum({})", actor(KAMEO_LIFECYCLE_RECEIVED_TOTAL)))
                            .legend("starts and stops"),
                    )
                    .target(
                        Target::new(format!("sum({})", actor(KAMEO_LINK_DIED_RECEIVED_TOTAL)))
                            .legend("linked actor deaths"),
                    )
                    .with_override(
                        FieldOverride::by_name("starts and stops").color(Color::fixed("blue")),
                    )
                    .with_override(
                        FieldOverride::by_name("linked actor deaths").color(Color::fixed("red")),
                    ),
            ],
        )
        .row(12, [warnings_and_errors()])
        // Last, as panels after a folded row fold into it once it is open.
        .folded(
            "${actor} · from traces",
            8,
            [
                from_traces(Panel::timeseries(format!(
                    "${{actor}} · {} handling time per message, from traces",
                    percentile_legend()
                )), true)
                .description(format!("At the percentile picked above. {HANDLING_TIME_DESCRIPTION} {FROM_TRACES_DESCRIPTION}"))
                .unit(Unit::Seconds)
                .target(traces(format!(
                    "{} | quantile_over_time(duration, {}) by (name)",
                    messages::of_actor(ACTOR_ATTRIBUTE),
                    selected_quantile(),
                ))),
                from_traces(Panel::timeseries("${actor} · handled per second by sender, from traces"), false)
                    .description(format!("Who keeps the actor busy. {FROM_TRACES_DESCRIPTION}"))
                    .unit(Unit::custom("msg/s"))
                    .stacking(StackingMode::Normal)
                    .target(traces(format!(
                        "{} | rate() by (span.{SENDER_ATTRIBUTE})",
                        messages::of_actor(ACTOR_ATTRIBUTE)
                    ))),
                from_traces(Panel::timeseries("${actor} · sent per second, from traces"), true)
                    .description(format!("What the actor asks of others. {FROM_TRACES_DESCRIPTION}"))
                    .unit(Unit::custom("msg/s"))
                    .stacking(StackingMode::Normal)
                    .target(traces(format!(
                        "{} | rate() by (name)",
                        messages::of_actor(SENDER_ATTRIBUTE)
                    ))),
            ],
        )
}

/// The selected actor's warnings and errors; the header links to all its logs
/// in Explore.
fn warnings_and_errors() -> Panel {
    let sequencer = format!(r#"{SEQUENCER_LABEL}="${SEQUENCER_VAR}""#);
    // The label Alloy reads off the kameo span a line was logged in.
    let actor_matcher = format!(r#"{ACTOR_LABEL}="${ACTOR_VAR}""#);
    Panel::logs("${actor} · warnings and errors")
        .description("Lines logged while the actor ran, from its own crate or from code it calls, e.g. the sequencer core. Tasks it spawns log without it.")
        .width(24)
        .header_link(
            "All logs in Explore",
            explore_logs_url(&super::logs(&[&sequencer, &actor_matcher])),
        )
        .target(Target::logs(super::logs(&[
            &sequencer,
            &actor_matcher,
            super::WARNINGS_AND_ERRORS,
        ])))
}
