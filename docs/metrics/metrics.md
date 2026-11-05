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

The exception is a gauge whose labels only exist at runtime and for which a `0` would be a false reading, like `actor_mailbox_capacity` (see [Actor metrics](#actor-metrics)): `sequencer_service_metrics` has no `init()`.

## Metrics in libraries

**Yes, record metrics from library crates.** The `metrics` facade is a no-op until a recorder is installed, so a library that records costs nothing to a consumer that never installs one — including tests. Libraries record; only the binary installs the exporter.

## Exporter setup

`sequencer_service`'s `main.rs` installs the Prometheus recorder on the config's `metrics_address` (default `0.0.0.0:9000`) with **explicit histogram buckets**. This matters: without buckets, `metrics-exporter-prometheus` renders histograms as rolling-window summaries whose quantiles **reset to `0`** once the window (default 60 s) drains — an idle period reads as "took 0 s" rather than "no data". With buckets you get real `_bucket`/`_sum`/`_count` counters that never decay, are aggregatable, and honour the dashboard's time range.

Ladders are matched by name suffix, so a new timing metric is covered automatically:

```rust
.set_buckets(COUNT_BUCKETS)                                                   // fallback
.set_buckets_for_metric(Matcher::Suffix("_seconds".to_owned()), LATENCY_BUCKETS)
```

## Actor metrics

Every actor's mailbox traffic comes from kameo itself: `sequencer_service` enables kameo's `metrics` feature, and kameo then counts on each mailbox, through the same recorder as everything else. Kameo names these series, not us, so their consts in `sequencer_service_metrics::names` are pinned by a test in `sequencer_service`'s `main.rs` that spawns an actor and checks what the recorder renders — a kameo upgrade that renames them fails there instead of blanking the dashboard.

| Metric | Type | Counts |
|---|---|---|
| `kameo_messages_sent_total` | counter | messages queued into the mailbox (`tell`, `ask`) |
| `kameo_messages_received_total` | counter | messages taken off it |
| `kameo_lifecycle_received_total` | counter | startup, stop, restart and callback signals taken off it |
| `kameo_link_died_received_total` | counter | deaths of linked actors taken off it |
| `actor_mailbox_capacity` | gauge | messages the mailbox holds before senders wait; **`+Inf` for an unbounded one** |

Every series is labelled `actor_name`: kameo's `Actor::name()`, which for a hand-written `impl Actor` is the full type name (`sequencer_executor_actor::actor::ExecutorActor<…StorageActor, …BedrockActor>`), and for `#[derive(Actor)]` just the ident (`Broker`). Each actor type has one series per sequencer, so two instances of one type would share it.

Sent minus received is the **backlog**: messages queued and not yet taken. The one being handled is already taken, so it does not count.

Kameo also exports `kameo_lifecycle_sent_total` and `kameo_link_died_sent_total`, which we leave out: kameo sends its own signals — startup, the stops a link triggers, every link-died notice — without counting them, so the sent side undercounts and link-died stays `0` forever. Only the received side is complete.

**Capacity** is ours: kameo exports none. `ActorHandle::new` records it from the mailbox itself (`ActorRef::mailbox_sender().max_capacity()`), so the dashboard never assumes a size. Every actor the service keeps a handle to is covered; the channel signer, which the executor owns, is recorded with an explicit `record_mailbox_capacity` call next to where the service gets its ref. An actor that is neither shows **no data** for its capacity, never a made-up one — when adding one, give it a handle or that call.

An unbounded mailbox exports infinity, which the exporter writes as Rust prints it, `inf`; Prometheus reads that as `+Inf`. In PromQL a backlog over `+Inf` is `0`, and `actor_mailbox_capacity < +Inf` keeps the bounded mailboxes only — what the dashboard's fill and capacity-line queries use, as Grafana cannot draw infinity.

Kameo only sees the mailbox: work an actor does inside its own `next()`, like the Bedrock actor's zone SDK events or the gossip actor's swarm events, is not in these counters.

## `dashboard_gen`

`tools/dashboard_gen` is a small Grafana dashboard builder plus the dashboard definitions. It prints JSON to stdout; the result is committed under `monitoring/grafana/dashboards/` and CI fails if it is stale.

```
src/lib.rs, schema.rs, styling.rs, unit.rs   the builder library
src/dashboards/<name>.rs                     one dashboard per module
src/main.rs                                  CLI: `dashboard_gen sequencer|network|actors`
```

Panels are built fluently, and every query is composed from the `names` consts:

```rust
Panel::timeseries("Block production rate")
    .width(18)
    .target(rate_per_min(&seq(sequencer_core_metrics::names::BLOCKS_PRODUCED_TOTAL), "blocks/min"))
```

Query helpers: `rate_per_min` for counters, `avg` for histograms, and `selected_percentile` for percentile lines — the latter reads a `percentile` dashboard dropdown created by `percentile_variable`, so one panel serves p50/p90/p95/p99 instead of drawing all four. Rate windows use `$__rate_interval`, which tracks the panel's zoom.

Helpers take a `Selector` (metric name plus label matchers: `label_eq` for `=`, `label_matches` for `=~`) rather than a bare name, so a scoped dashboard scopes every series, histogram `_bucket`/`_sum`/`_count` included.

### One sequencer at a time

Every sequencer exports the same metric names, so an unscoped query mixes all of them. To tell them apart, `sequencer_service` labels every series it exports with its channel signing public key, in hex — the key `setup` prints and `stake --sequencer-key` takes:

```
chain_height{sequencer="b0af2105…c68c"} 42
```

The label name is `sequencer_service_metrics::names::SEQUENCER_LABEL`. The **Sequencer** dashboard (`dashboards/sequencer.rs`) has a **Sequencer** dropdown (`label_values_variable`, listing the `sequencer` values of `chain_height`), and its `seq(name)` helper pins every query to `sequencer="$sequencer"`.

Keys identify any sequencer, external ones included, with no scrape config. Where readable names are known, the scrape config can set them instead: a target label wins over a scraped one, and Prometheus keeps the scraped value as `exported_sequencer`. The devnet's `monitoring/prometheus/prometheus.yml` does this, naming its nodes `sequencer_0`…`sequencer_3`.

### The network at a glance

The **Network** dashboard (`dashboards/network.rs`) puts every sequencer side by side; all the dashboards link to each other in the top bar, and clicking a sequencer's series opens its own dashboard.

Titles carry no "Sequencer" prefix, since every dashboard here is about sequencers; the per-sequencer one is named **Sequencer** because one sequencer is what it shows. The `sequencer` tag and the uids (`sequencer`, `sequencer-network`, `sequencer-actors`) still carry the prefix, keeping these dashboards apart in a Grafana shared with others.

| Question | Panel |
|---|---|
| Who may write now, and how does the turn rotate? | **Turn to write** — a state timeline of `turn_to_write`, one row per sequencer |
| Who produces the blocks? | **Blocks produced over time** — a heatmap: a cell per sequencer per slice of time (≥ 1 min), darker for more blocks |
| Is the rotation fair, and are turns used? | **Share of turns**, **Share of blocks produced**, **Blocks per turn** over the time range |
| Is anyone falling behind or failing? | **Blocks behind the network**, **Failed production turns in a row** |

`blocks_produced_total` counts a block once the channel finalizes it, signed by this sequencer: a block on the head can still be orphaned when another sequencer's inscription wins the same position, typically around a turn handover. Summed over sequencers it equals the finalized chain height, as long as none restarted.

Turns come from Bedrock: the zone SDK notifies a sequencer when its turn to write starts and ends, and the Bedrock actor forwards that to the executor. `sequencer_executor_actor_metrics` records them as `turn_to_write` (1 while held) and `turns_to_write_total` (turns started; a turn notified several times counts once, while a new starting slot is a new turn even for the same holder).

### One actor at a time

The **Actors** dashboard (`dashboards/actors.rs`) reads the [actor metrics](#actor-metrics) of one sequencer, picked from the **Sequencer** dropdown. Its top half compares all of that sequencer's actors; clicking one shows it in the bottom half, which follows the **Actor** dropdown.

| Question | Panel |
|---|---|
| Which actors do the most work? | **All actors · messages handled over the time range**, **… per second** |
| Is any mailbox filling up? | **All actors · fullest mailbox over the time range** — the highest backlog as a share of capacity; unbounded mailboxes have no fill and are left out |
| Is a backlog building? | **All actors · mailbox backlog**, and for the picked actor **mailbox backlog vs capacity**, its capacity drawn as a dashed line |
| How does the picked actor keep up? | **messages per second** (sent vs handled), **backlog**, **mailbox capacity** (`unbounded` for `+Inf`), **mailbox fill** (green, orange from 50%, red from 90%) |
| Was it restarted? | **lifecycle and link signals since startup** — starts and stops read 1 after one start, more after a restart |

Actors appear by type name alone (`ExecutorActor`, `StorageActor`, `Broker`): the queries cut the module path and generic arguments off `actor_name` with `label_replace`, and the **Actor** dropdown does the same with a variable regex (`Variable::regex`). Its value is that short name, so queries pick the actor back with `actor_name=~"(?:[a-z0-9_]+::)*$actor(?:<.*)?"` — anchored, so picking `StorageActor` does not also pick `ExecutorActor<…StorageActor…>`.

**Extending it:**

| Goal | Change |
|---|---|
| New panel | Add a `Panel::…` to a row in the dashboard module |
| New dashboard | `src/dashboards/<name>.rs` with `pub fn dashboard()`, a `pub mod` line, a `DashboardKind` variant, and a `just regenerate-dashboards` line |
| Grafana option we don't model yet | Add the field to `schema.rs` and a setter on `Panel` (styling setters live in `styling.rs` and panic when handed a redundant default) |

The builder deliberately models only the subset of Grafana's schema we use.

## Logs

`--profile monitoring` also runs **Loki** and **Alloy**: Alloy reads this compose project's container output through the Docker socket and ships it to Loki, which Grafana has as its `loki` datasource; its API is also on the host at `:3100`, for `logcli` or `curl`. Config: `monitoring/alloy/config.alloy`, `monitoring/loki/loki.yml`.

Every stream is labelled `service_name` (the compose service), every line `level` (`INFO`, `WARN`, …), and a sequencer's stream also `sequencer` — `sequencer_0`…`sequencer_3`, the same names Prometheus gives them, so one Sequencer dropdown filters metrics and logs alike.

Read logs in **Explore** or **Drilldown → Logs**; the dashboards only point at them:

| Dashboard | Panel |
|---|---|
| Sequencer | **Warnings and errors** of the selected sequencer, with a header link to all its logs in Explore |
| Network | **Warnings per minute** and **Errors per minute** per sequencer, linking to them in Explore |

`dashboard_gen` builds log queries with `Target::logs`, a log list with `Panel::logs`, and Explore links with `explore_logs_url`. A natively run sequencer (`just run-sequencer`) is not in Docker, so its logs stay in the terminal.

## Justfile

| Recipe | Purpose |
|---|---|
| `just regenerate-dashboards` | Rebuild the committed dashboard JSON. Run after touching metric names or dashboard code — CI checks it is current. |
| `just run-monitoring` | Prometheus (`:9090`), Loki (`:3100`) + Alloy, and Grafana (`:3000`, anonymous admin) in docker, scraping the sequencers every 5 s and collecting container logs |
| `just get-sequencer-metrics` | `curl` the raw `/metrics` endpoint — quickest way to confirm a metric name and value |
