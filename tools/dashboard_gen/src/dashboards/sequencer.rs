//! The sequencer dashboard: chain progress, block timings, mempool and
//! transaction outcomes.

#![expect(
    clippy::non_ascii_literal,
    reason = "legend separators use `·` intentionally, matching the rendered Grafana labels"
)]

use dashboard_gen::{
    Color, Dashboard, FieldOverride, GradientMode, Panel, Target, Thresholds, Unit, avg,
    percentile_legend, percentile_variable, rate_per_min, selected_percentile,
};

const PERCENTILES: &[u32] = &[50, 90, 95, 99];
const DEFAULT_PERCENTILE: u32 = 95;

pub fn dashboard() -> Dashboard {
    Dashboard::new("Sequencer", "sequencer")
        .tag("sequencer")
        .variable(percentile_variable(PERCENTILES, DEFAULT_PERCENTILE))
        .row(
            7,
            [
                Panel::stat("Chain height")
                    .width(6)
                    .unit(Unit::Short)
                    .decimals(0)
                    .color(Color::fixed("blue"))
                    .target(
                        Target::new(sequencer_core_metrics::names::CHAIN_HEIGHT).legend("height"),
                    ),
                Panel::stat("Blocks produced by this sequencer since startup")
                    .width(6)
                    .unit(Unit::Short)
                    .decimals(0)
                    .color(Color::fixed("green"))
                    .target(
                        Target::new(sequencer_core_metrics::names::BLOCKS_PRODUCED_TOTAL)
                            .legend("produced"),
                    ),
                Panel::timeseries("Block production rate")
                    .width(12)
                    .unit(Unit::Short)
                    .target(rate_per_min(
                        sequencer_core_metrics::names::BLOCKS_PRODUCED_TOTAL,
                        "produced · blocks/min",
                    ))
                    .with_override(
                        FieldOverride::by_name("produced · blocks/min").color(Color::fixed("green")),
                    ),
            ],
        )
        .row(
            9,
            [Panel::timeseries("Block creation time")
                .width(24)
                .unit(Unit::Seconds)
                .target(selected_percentile(
                    sequencer_core_metrics::names::BLOCK_CREATION_TIME,
                    &[],
                    &percentile_legend(),
                ))
                .target(avg(sequencer_core_metrics::names::BLOCK_CREATION_TIME))
                .with_override(
                    FieldOverride::by_name("avg")
                        .dashed_line()
                        .color(Color::fixed("text")),
                )],
        )
        .row(
            9,
            [
                Panel::timeseries("Transaction application time")
                    .width(12)
                    .unit(Unit::Seconds)
                    .target(selected_percentile(
                        sequencer_core_metrics::names::MEMPOOL_TRANSACTION_APPLICATION_TIME,
                        &["kind", "origin", "status"],
                        "{{kind}} · {{origin}} · {{status}}",
                    )),
                Panel::timeseries("Transactions per block")
                    .width(12)
                    .unit(Unit::Short)
                    .target(selected_percentile(
                        sequencer_core_metrics::names::TRANSACTIONS_PER_BLOCK,
                        &[],
                        &percentile_legend(),
                    ))
                    .target(avg(sequencer_core_metrics::names::TRANSACTIONS_PER_BLOCK))
                    .with_override(
                        FieldOverride::by_name("avg")
                            .dashed_line()
                            .color(Color::fixed("text")),
                    ),
            ],
        )
        .row(
            8,
            [
                Panel::gauge("Mempool utilization")
                    .width(6)
                    .unit(Unit::Percent)
                    .decimals(1)
                    .min(0.0)
                    .max(100.0)
                    .thresholds(
                        Thresholds::base("green")
                            .step(70.0, "orange")
                            .step(90.0, "red"),
                    )
                    .target(
                        Target::new(format!(
                            "100 * {size} / {max_size}",
                            size = sequencer_core_metrics::names::MEMPOOL_SIZE,
                            max_size = sequencer_core_metrics::names::MEMPOOL_MAX_SIZE,
                        ))
                        .legend("utilization"),
                    ),
                Panel::timeseries("Mempool size vs capacity")
                    .width(18)
                    .unit(Unit::Short)
                    .span_nulls()
                    .min(0.0)
                    .target(
                        Target::new(sequencer_core_metrics::names::MEMPOOL_SIZE).legend("queued"),
                    )
                    .target(
                        Target::new(sequencer_core_metrics::names::MEMPOOL_MAX_SIZE)
                            .legend("capacity"),
                    )
                    .with_override(
                        FieldOverride::by_name("capacity")
                            .dashed_line()
                            .color(Color::fixed("red")),
                    )
                    .with_override(FieldOverride::by_name("queued").color(Color::fixed("blue"))),
            ],
        )
        .row(
            8,
            [
                Panel::gauge("Failed transactions share")
                    .width(6)
                    .unit(Unit::Percent)
                    .decimals(2)
                    .min(0.0)
                    .max(100.0)
                    .thresholds(
                        Thresholds::base("green")
                            .step(1.0, "orange")
                            .step(5.0, "red"),
                    )
                    .target(
                        Target::new(format!(
                            // Both failure stages against the same submission base;
                            // `clamp_min` keeps an idle window (nothing submitted)
                            // reading as 0% instead of a division by zero.
                            "100 * (increase({before_mempool}[$__range]) + increase({in_mempool}[$__range])) / clamp_min(increase({submitted}[$__range]), 1)",
                            before_mempool = sequencer_service_metrics::names::BEFORE_MEMPOOL_FAILED_TRANSACTIONS_TOTAL,
                            in_mempool = sequencer_core_metrics::names::MEMPOOL_FAILED_TRANSACTIONS_TOTAL,
                            submitted = sequencer_service_metrics::names::SUBMITTED_TRANSACTIONS_TOTAL,
                        ))
                        .legend("failed"),
                    ),
                Panel::timeseries("Submitted vs failed transactions (per minute)")
                    .width(18)
                    .unit(Unit::Short)
                    .min(0.0)
                    .fill_opacity(35)
                    .gradient_mode(GradientMode::Opacity)
                    .target(rate_per_min(
                        sequencer_service_metrics::names::SUBMITTED_TRANSACTIONS_TOTAL,
                        "submitted",
                    ))
                    .target(rate_per_min(
                        sequencer_service_metrics::names::BEFORE_MEMPOOL_FAILED_TRANSACTIONS_TOTAL,
                        "failed · before mempool",
                    ))
                    .target(rate_per_min(
                        sequencer_core_metrics::names::MEMPOOL_FAILED_TRANSACTIONS_TOTAL,
                        "failed · in mempool",
                    ))
                    .with_override(
                        FieldOverride::by_name("submitted").color(Color::fixed("green")),
                    )
                    .with_override(
                        FieldOverride::by_name("failed · before mempool")
                            .color(Color::fixed("orange")),
                    )
                    .with_override(
                        FieldOverride::by_name("failed · in mempool").color(Color::fixed("red")),
                    ),
            ],
        )
}
