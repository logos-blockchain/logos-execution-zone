//! The actors dashboard: mailbox traffic of one sequencer's actors, as kameo
//! counts it, side by side and then of one actor picked from a dropdown.
//!
//! Actors go by their type name alone, e.g. `ExecutorActor`: kameo labels
//! series with the full type, module path and generic arguments included.

#![expect(
    clippy::non_ascii_literal,
    reason = "titles and legends use `·` intentionally, matching the other dashboards"
)]

use dashboard_gen::{
    Color, Dashboard, FieldOverride, Panel, Selector, Target, Thresholds, Unit,
    label_values_variable,
};
use sequencer_service_metrics::names::{
    ACTOR_MAILBOX_CAPACITY, ACTOR_NAME_LABEL, KAMEO_LIFECYCLE_RECEIVED_TOTAL,
    KAMEO_LINK_DIED_RECEIVED_TOTAL, KAMEO_MESSAGES_RECEIVED_TOTAL, KAMEO_MESSAGES_SENT_TOTAL,
    SEQUENCER_LABEL,
};

use super::sequencer::SEQUENCER_VAR;

pub const UID: &str = "sequencer-actors";

/// Dashboard variable holding the type name of the actor the detail panels show.
const ACTOR_VAR: &str = "actor";

/// Label the overview queries put each actor's type name in.
const ACTOR_LABEL: &str = "actor";

/// The module path ahead of the type name in [`ACTOR_NAME_LABEL`], e.g.
/// `sequencer_storage_actor::actor::`. Derived actors have none.
const MODULE_PATH: &str = "(?:[a-z0-9_]+::)*";

/// An actor's type name, without its generic arguments.
const TYPE_NAME: &str = "[A-Za-z0-9_]+";

const LEGEND_PER_ACTOR: &str = "{{actor}}";

const BACKLOG_DESCRIPTION: &str = "Messages sent to the actor and not yet taken off its mailbox.";

const FILL_DESCRIPTION: &str = "Backlog as a share of the mailbox capacity: at 100%, senders wait. An unbounded mailbox never fills, so it has no fill.";

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

/// `expr` summed down to one series per actor, its type name in [`ACTOR_LABEL`].
fn per_actor(expr: &str) -> String {
    format!(
        r#"label_replace(sum by ({ACTOR_NAME_LABEL}) ({expr}), "{ACTOR_LABEL}", "$1", "{ACTOR_NAME_LABEL}", "{MODULE_PATH}({TYPE_NAME}).*")"#
    )
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

fn fill_thresholds() -> Thresholds {
    Thresholds::base("green")
        .step(50.0, "orange")
        .step(90.0, "red")
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

pub fn dashboard() -> Dashboard {
    Dashboard::new("Actors", UID)
        .tag(super::TAG)
        .link_tagged("Dashboards", super::TAG)
        .variable(label_values_variable(
            SEQUENCER_VAR,
            "Sequencer",
            KAMEO_MESSAGES_RECEIVED_TOTAL,
            SEQUENCER_LABEL,
        ))
        .variable(
            label_values_variable(
                ACTOR_VAR,
                "Actor",
                &all_actors(KAMEO_MESSAGES_RECEIVED_TOTAL).to_string(),
                ACTOR_NAME_LABEL,
            )
            .regex(format!("/^{MODULE_PATH}({TYPE_NAME})/")),
        )
        .row(
            8,
            [
                per_actor_panel(Panel::bar_gauge("All actors · messages handled over the time range"))
                    .width(12)
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
                per_actor_panel(Panel::bar_gauge("All actors · fullest mailbox over the time range"))
                    .description(FILL_DESCRIPTION)
                    .width(12)
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
            ],
        )
        .row(
            9,
            [
                per_actor_panel(Panel::timeseries("All actors · messages handled per second"))
                    .width(12)
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
                    .width(12)
                    .min(0.0)
                    .color(Color::palette_classic())
                    .target(Target::new(backlog_per_actor()).legend(LEGEND_PER_ACTOR)),
            ],
        )
        .row(
            5,
            [
                Panel::stat("${actor} · messages handled since startup")
                    .width(6)
                    .decimals(0)
                    .color(Color::fixed("blue"))
                    .target(
                        Target::new(format!("sum({})", actor(KAMEO_MESSAGES_RECEIVED_TOTAL)))
                            .legend("handled"),
                    ),
                Panel::stat("${actor} · messages handled per second")
                    .width(6)
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
                    .width(6)
                    .decimals(0)
                    .color(Color::fixed("orange"))
                    .target(Target::new(backlog()).legend("queued")),
                Panel::stat("${actor} · mailbox capacity")
                    .description("Messages the mailbox holds before senders wait, as read off the mailbox at startup.")
                    .width(6)
                    .decimals(0)
                    .color(Color::fixed("text"))
                    // Grafana matches mappings on the value's JavaScript string.
                    .value_mapping("Infinity", "unbounded", "text")
                    .target(Target::new(capacity()).legend("capacity")),
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
            9,
            [
                Panel::timeseries("${actor} · messages per second")
                    .description("Sent: queued into the mailbox. Handled: taken off it. Sent staying above handled grows the backlog.")
                    .width(12)
                    .min(0.0)
                    .target(
                        Target::new(format!(
                            "sum(rate({}[$__rate_interval]))",
                            actor(KAMEO_MESSAGES_SENT_TOTAL)
                        ))
                        .legend("sent"),
                    )
                    .target(
                        Target::new(format!(
                            "sum(rate({}[$__rate_interval]))",
                            actor(KAMEO_MESSAGES_RECEIVED_TOTAL)
                        ))
                        .legend("handled"),
                    )
                    .with_override(FieldOverride::by_name("sent").color(Color::fixed("blue")))
                    .with_override(FieldOverride::by_name("handled").color(Color::fixed("green"))),
                Panel::timeseries("${actor} · lifecycle and link signals since startup")
                    .description("Signals the actor handled, as running totals. One start reads 1; more means the actor was stopped and started again. Linked actor deaths stay 0 unless the actor is linked to others.")
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
}
