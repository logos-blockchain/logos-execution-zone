# Metrics

Services expose Prometheus metrics; Grafana dashboards are generated from Rust so panel queries and metric names cannot drift apart.

## Metrics crates

Every crate that emits metrics gets a sibling `metrics` crate — `lez/sequencer/core/metrics` → `sequencer_core_metrics`. Each has two halves:

| Module | Gated by | Contents |
|---|---|---|
| `names` | always compiled | `pub const BLOCKS_PRODUCED_TOTAL: &str = "blocks_produced_total";` — one const per metric |
| `record` | `record` feature | `record_*` / `increment_*` functions, plus `init()` |

The emitting crate depends on it with `features = ["record"]`; consumers that only need the names (i.e. `dashboard_gen`) take the default features and pull in nothing. Dashboards reference the same consts the recording code does, so **renaming a metric is a compile error rather than a silently empty panel**.

## Naming

The recorder runs with `with_recommended_naming(true)`, which enforces Prometheus convention:

| Kind | Suffix | Example |
|---|---|---|
| Counter | `_total` | `blocks_produced_total`, `submitted_transactions_total` |
| Histogram | unit | `block_creation_time_seconds` |
| Gauge | none | `mempool_size` |

**Spell the suffix in the const.** The exporter appends a missing unit suffix to the *rendered* name, but bucket matchers (below) run against the registered name — a duration metric named without `_seconds` renders correctly yet silently gets the wrong buckets.

## Metric types

| Type | Use for | Example |
|---|---|---|
| Counter | monotonically increasing event counts | `mempool_failed_transactions_total` |
| Gauge | a value that moves both ways | `mempool_size`, `chain_height` (a reorg lowers it) |
| Histogram | distributions — latencies, sizes, per-batch counts | `mempool_transaction_application_time_seconds` |

Each metric gets a private constructor plus a public recording wrapper, so its description, unit and labels are declared once:

```rust
fn blocks_produced_total_counter() -> Counter {
    counter!(
        description: "Number of blocks produced by this sequencer and applied to the head",
        unit: Unit::Count,
        names::BLOCKS_PRODUCED_TOTAL
    )
}

pub fn increment_blocks_produced_total() {
    blocks_produced_total_counter().increment(1);
}
```

Labels are passed as `"origin" => <&'static str>::from(origin)`; keep them low-cardinality (enums, never IDs or hashes).

## `init()`

Each `record` module exposes `init()`, called once at startup after the recorder is installed. It publishes every metric at zero.

This is not cosmetic. A metric only materialises when first touched, and `rate()`/`increase()` need a sample from *before* an increment to see it — a series that springs into existence at `1` reads as `0` until the second event, so the first one is lost forever. Zero-publishing also means an idle service exports `0` instead of nothing at all.

For histograms, creating the handle publishes zeroed buckets without recording an observation (recording a fake `0` would skew the distribution). Label combinations must each be registered, so `init()` iterates the label enums via `strum::EnumIter`.

## Metrics in libraries

**Yes, record metrics from library crates.** The `metrics` facade is a no-op until a recorder is installed, so a library that records costs nothing to a consumer that never installs one — including tests. Libraries record; only the binary installs the exporter.

## Exporter setup

`sequencer_service`'s `main.rs` installs the Prometheus recorder on the config's `metrics_address` (default `0.0.0.0:9000`) with **explicit histogram buckets**. This matters: without buckets, `metrics-exporter-prometheus` renders histograms as rolling-window summaries whose quantiles **reset to `0`** once the window (default 60 s) drains — an idle period reads as "took 0 s" rather than "no data". With buckets you get real `_bucket`/`_sum`/`_count` counters that never decay, are aggregatable, and honour the dashboard's time range.

Ladders are matched by name suffix, so a new timing metric is covered automatically:

```rust
.set_buckets(COUNT_BUCKETS)                                                   // fallback
.set_buckets_for_metric(Matcher::Suffix("_seconds".to_owned()), LATENCY_BUCKETS)
```

## `dashboard_gen`

`tools/dashboard_gen` is a small Grafana dashboard builder plus the dashboard definitions. It prints JSON to stdout; the result is committed under `monitoring/grafana/dashboards/` and CI fails if it is stale.

```
src/lib.rs, schema.rs, styling.rs, unit.rs   the builder library
src/dashboards/<name>.rs                     one dashboard per module
src/main.rs                                  CLI: `dashboard_gen sequencer`
```

Panels are built fluently, and every query is composed from the `names` consts:

```rust
Panel::timeseries("Block production rate")
    .width(18)
    .target(rate_per_min(sequencer_core_metrics::names::BLOCKS_PRODUCED_TOTAL, "blocks/min"))
```

Query helpers: `rate_per_min` for counters, `avg` for histograms, and `selected_percentile` for percentile lines — the latter reads a `percentile` dashboard dropdown created by `percentile_variable`, so one panel serves p50/p90/p95/p99 instead of drawing all four. Rate windows use `$__rate_interval`, which tracks the panel's zoom.

**Extending it:**

| Goal | Change |
|---|---|
| New panel | Add a `Panel::…` to a row in the dashboard module |
| New dashboard | `src/dashboards/<name>.rs` with `pub fn dashboard()`, a `pub mod` line, a `DashboardKind` variant, and a `just regenerate-dashboards` line |
| Grafana option we don't model yet | Add the field to `schema.rs` and a setter on `Panel` (styling setters live in `styling.rs` and panic when handed a redundant default) |

The builder deliberately models only the subset of Grafana's schema we use.

## Justfile

| Recipe | Purpose |
|---|---|
| `just regenerate-dashboards` | Rebuild the committed dashboard JSON. Run after touching metric names or dashboard code — CI checks it is current. |
| `just run-monitoring` | Prometheus (`:9090`) + Grafana (`:3000`, anonymous admin) in docker, scraping the sequencer every 5 s |
| `just get-sequencer-metrics` | `curl` the raw `/metrics` endpoint — quickest way to confirm a metric name and value |
