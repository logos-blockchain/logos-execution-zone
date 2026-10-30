//! The network dashboard: every sequencer side by side — who holds the turn to
//! write, who proposes the blocks, and who falls behind.

use dashboard_gen::{
    Color, Dashboard, Panel, Selector, Target, Thresholds, Unit, percentile_variable,
    selected_percentile, sum_rate_per_min,
};
use sequencer_core_metrics::names::{
    BLOCK_CREATION_TIME, BLOCKS_PRODUCED_TOTAL, CHAIN_HEIGHT, MEMPOOL_FAILED_TRANSACTIONS_TOTAL,
    MEMPOOL_MAX_SIZE, MEMPOOL_SIZE,
};
use sequencer_executor_actor_metrics::names::{
    PRODUCTION_FAILED_ATTEMPTS, TURN_TO_WRITE, TURNS_TO_WRITE_TOTAL,
};
use sequencer_rpc_server_actor_metrics::names::{
    BEFORE_MEMPOOL_FAILED_TRANSACTIONS_TOTAL, SUBMITTED_TRANSACTIONS_TOTAL,
};
use sequencer_service_metrics::names::SEQUENCER_LABEL;

use super::sequencer;

const PERCENTILES: &[u32] = &[50, 90, 95, 99];
const DEFAULT_PERCENTILE: u32 = 95;

/// Legend naming each series after its sequencer.
const PER_SEQUENCER: &str = "{{sequencer}}";

/// Every sequencer's series of `metric`.
fn all(metric: &str) -> Selector {
    Selector::new(metric)
}

/// `expr` summed down to one series per sequencer.
fn by_sequencer(expr: &str) -> String {
    format!("sum by ({SEQUENCER_LABEL}) ({expr})")
}

/// The network's average per-minute increase of `counter` over the time range.
/// Steadier than a rate: blocks come in bursts, one turn at a time.
fn per_minute_over_range(counter: &str, legend: &str) -> Target {
    Target::new(format!(
        "sum(increase({}[$__range])) / ($__range_s / 60)",
        all(counter)
    ))
    .legend(legend)
    .instant()
}

/// Each sequencer's percentage of `counter`'s increase over the time range,
/// largest first.
fn share_over_range(counter: &str) -> Target {
    let increase = format!("increase({}[$__range])", all(counter));
    Target::new(format!(
        // `on() group_left` divides every sequencer by the one total;
        // `clamp_min` reads an idle range as 0% rather than dividing by zero.
        "sort_desc(100 * {per_sequencer} / on() group_left() clamp_min(sum({increase}), 1))",
        per_sequencer = by_sequencer(&increase),
    ))
    .legend(PER_SEQUENCER)
    .instant()
}

/// A bar gauge comparing sequencers on one measure: bars share one color, as
/// the names beside them already tell sequencers apart.
fn ranking(title: &str) -> Panel {
    per_sequencer(Panel::bar_gauge(title)).color(Color::fixed("blue"))
}

/// A panel comparing sequencers, in distinct colors; a click opens the
/// sequencer's own dashboard.
fn per_sequencer(panel: Panel) -> Panel {
    panel.color(Color::palette_classic()).link(
        "Open this sequencer's dashboard",
        format!(
            "/d/{uid}?var-{var}=${{__field.labels.{SEQUENCER_LABEL}}}&${{__url_time_range}}",
            uid = sequencer::UID,
            var = sequencer::SEQUENCER_VAR,
        ),
    )
}

pub fn dashboard() -> Dashboard {
    Dashboard::new("Sequencer network", "sequencer-network")
        .tag(super::TAG)
        .link_tagged("Sequencer dashboards", super::TAG)
        .variable(percentile_variable(PERCENTILES, DEFAULT_PERCENTILE))
        .row(
            5,
            [
                Panel::stat("Sequencers reporting")
                    .width(4)
                    .decimals(0)
                    .color(Color::fixed("text"))
                    .target(
                        Target::new(format!("count({})", by_sequencer(&all(CHAIN_HEIGHT).to_string())))
                            .legend("sequencers"),
                    ),
                Panel::stat("Network height")
                    .width(4)
                    .decimals(0)
                    .color(Color::fixed("blue"))
                    .target(Target::new(format!("max({})", all(CHAIN_HEIGHT))).legend("height")),
                Panel::stat("Height spread")
                    .description("Blocks between the highest and the lowest sequencer. A growing spread is a sequencer falling behind.")
                    .width(4)
                    .decimals(0)
                    .thresholds(Thresholds::base("green").step(2.0, "orange").step(5.0, "red"))
                    .target(
                        Target::new(format!(
                            "max({height}) - min({height})",
                            height = all(CHAIN_HEIGHT),
                        ))
                        .legend("spread"),
                    ),
                Panel::stat("Blocks per minute")
                    .description("Average over the time range.")
                    .width(4)
                    .decimals(1)
                    .color(Color::fixed("green"))
                    .target(per_minute_over_range(BLOCKS_PRODUCED_TOTAL, "blocks/min")),
                Panel::stat("Txs per minute")
                    .description("Transactions submitted, averaged over the time range.")
                    .width(4)
                    .decimals(1)
                    .color(Color::fixed("text"))
                    .target(per_minute_over_range(SUBMITTED_TRANSACTIONS_TOTAL, "txs/min")),
                Panel::stat("Failing sequencers")
                    .description("Sequencers whose last production turn failed.")
                    .width(4)
                    .decimals(0)
                    .thresholds(Thresholds::base("green").step(1.0, "red"))
                    .target(
                        Target::new(format!(
                            // `or vector(0)`: `count` of nothing is no data, not zero.
                            "count({} > 0) or vector(0)",
                            all(PRODUCTION_FAILED_ATTEMPTS),
                        ))
                        .legend("failing"),
                    ),
            ],
        )
        .row(
            7,
            [per_sequencer(Panel::state_timeline("Turn to write"))
                .description("Which sequencer may write to the channel, over time.")
                .width(24)
                .value_mapping("0", "waiting", "transparent")
                .value_mapping("1", "writing", "blue")
                .target(
                    Target::new(format!("max by ({SEQUENCER_LABEL}) ({})", all(TURN_TO_WRITE)))
                        .legend(PER_SEQUENCER),
                )],
        )
        .row(
            8,
            [per_sequencer(Panel::status_history("Blocks proposed over time"))
                .description("Blocks each sequencer proposed in each slice of time; darker is more.")
                .width(24)
                .decimals(0)
                .min(0.0)
                .color(Color::continuous_blues())
                // At least a minute per cell, and no more than 60 cells across.
                .min_interval("1m")
                .max_data_points(60)
                .target(
                    Target::new(by_sequencer(&format!(
                        // Exact counts per cell: `increase` would extrapolate
                        // to fractions. `clamp_min` hides a restart's reset.
                        "clamp_min({blocks} - {blocks} offset $__interval, 0)",
                        blocks = all(BLOCKS_PRODUCED_TOTAL),
                    )))
                    .legend(PER_SEQUENCER),
                )],
        )
        .row(
            8,
            [
                ranking("Share of turns")
                    .description("Each sequencer's part of the turns to write given out over the time range.")
                    .width(8)
                    .unit(Unit::Percent)
                    .decimals(0)
                    .min(0.0)
                    .max(100.0)
                    .target(share_over_range(TURNS_TO_WRITE_TOTAL)),
                ranking("Share of blocks proposed")
                    .description("Each sequencer's part of the blocks proposed over the time range.")
                    .width(8)
                    .unit(Unit::Percent)
                    .decimals(0)
                    .min(0.0)
                    .max(100.0)
                    .target(share_over_range(BLOCKS_PRODUCED_TOTAL)),
                ranking("Blocks per turn")
                    .description("Blocks proposed per turn to write over the time range. A sequencer well below the rest lets its turns go by.")
                    .width(8)
                    .decimals(1)
                    .min(0.0)
                    .target(
                        Target::new(format!(
                            // `> 0` leaves out sequencers that had no turn.
                            "sort_desc({blocks} / ({turns} > 0))",
                            blocks = by_sequencer(&format!(
                                "increase({}[$__range])",
                                all(BLOCKS_PRODUCED_TOTAL)
                            )),
                            turns = by_sequencer(&format!(
                                "increase({}[$__range])",
                                all(TURNS_TO_WRITE_TOTAL)
                            )),
                        ))
                        .legend(PER_SEQUENCER)
                        .instant(),
                    ),
            ],
        )
        .row(
            11,
            [
                per_sequencer(Panel::timeseries("Blocks behind the network"))
                    .description("How far each sequencer's chain height trails the highest one.")
                    .width(12)
                    .min(0.0)
                    .target(
                        Target::new(format!(
                            "scalar(max({height})) - max by ({SEQUENCER_LABEL}) ({height})",
                            height = all(CHAIN_HEIGHT),
                        ))
                        .legend(PER_SEQUENCER),
                    ),
                per_sequencer(Panel::timeseries("Failed production turns in a row"))
                    .width(12)
                    .min(0.0)
                    .target(
                        Target::new(format!(
                            "max by ({SEQUENCER_LABEL}) ({})",
                            all(PRODUCTION_FAILED_ATTEMPTS)
                        ))
                        .legend(PER_SEQUENCER),
                    ),
            ],
        )
        .row(
            11,
            [
                per_sequencer(Panel::timeseries("Block creation time"))
                    .width(12)
                    .unit(Unit::Seconds)
                    .target(selected_percentile(
                        &all(BLOCK_CREATION_TIME),
                        &[SEQUENCER_LABEL],
                        PER_SEQUENCER,
                    )),
                per_sequencer(Panel::timeseries("Mempool utilization"))
                    .width(12)
                    .unit(Unit::Percent)
                    .min(0.0)
                    .max(100.0)
                    .target(
                        Target::new(format!(
                            "100 * max by ({SEQUENCER_LABEL}) ({size}) / max by ({SEQUENCER_LABEL}) ({max_size})",
                            size = all(MEMPOOL_SIZE),
                            max_size = all(MEMPOOL_MAX_SIZE),
                        ))
                        .legend(PER_SEQUENCER),
                    ),
            ],
        )
        .row(
            11,
            [
                per_sequencer(Panel::timeseries("Transactions submitted per minute"))
                    .width(12)
                    .min(0.0)
                    .target(sum_rate_per_min(
                        &all(SUBMITTED_TRANSACTIONS_TOTAL),
                        &[SEQUENCER_LABEL],
                        PER_SEQUENCER,
                    )),
                per_sequencer(Panel::timeseries("Failed transactions per minute"))
                    .description("Rejected before reaching the mempool, plus dropped from it.")
                    .width(12)
                    .min(0.0)
                    .target(
                        Target::new(format!(
                            "60 * ({before_mempool} + {in_mempool})",
                            before_mempool = by_sequencer(&format!(
                                "rate({}[$__rate_interval])",
                                all(BEFORE_MEMPOOL_FAILED_TRANSACTIONS_TOTAL)
                            )),
                            in_mempool = by_sequencer(&format!(
                                "rate({}[$__rate_interval])",
                                all(MEMPOOL_FAILED_TRANSACTIONS_TOTAL)
                            )),
                        ))
                        .legend(PER_SEQUENCER),
                    ),
            ],
        )
}
