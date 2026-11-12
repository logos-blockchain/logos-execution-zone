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

Every actor's mailbox traffic comes from kameo itself: `sequencer_service` enables kameo's `metrics` feature, and kameo then counts on each mailbox, through the same recorder as everything else. Kameo names these series, not us, so their consts in `sequencer_service_metrics::names` are pinned by a test in `sequencer_service`'s `main.rs` that spawns an actor and checks what the recorder renders — a kameo upgrade that renames them fails there instead of blanking the dashboard. Handling time and lifecycle come from kameo's tracing instead ([below](#handling-time-and-lifecycle)).

| Metric | Type | Counts |
|---|---|---|
| `kameo_messages_sent_total` | counter | messages queued into the mailbox (`tell`, `ask`) |
| `kameo_messages_received_total` | counter | messages taken off it |
| `kameo_lifecycle_received_total` | counter | startup, stop, restart and callback signals taken off it |
| `kameo_link_died_received_total` | counter | deaths of linked actors taken off it |
| `actor_mailbox_capacity` | gauge | messages the mailbox holds before senders wait; **`+Inf` for an unbounded one** |
| `actor_message_handling_time_seconds` | histogram | time from taking a message off the mailbox to its handler returning |
| `actor_state` | gauge | `0` stopped, `1` running, `2` restarting, `3` failed — `names::ActorState` |
| `actor_start_time_seconds` | gauge | Unix time the actor last started; it changes on every restart |

Every series is labelled `actor_name`: kameo's `Actor::name()`, which for a hand-written `impl Actor` is the full type name (`sequencer_executor_actor::actor::ExecutorActor<…StorageActor, …BedrockActor>`), and for `#[derive(Actor)]` just the ident (`Broker`). Each actor type has one series per sequencer, so two instances of one type would share it.

`actor_message_handling_time_seconds` is also labelled `message_name`: kameo's `Message::name()`, by default the message's full type name, as kameo puts it on its `actor.handle_message` span. And `sender`: what sent the message ([below](#handling-time-and-lifecycle)).

Sent minus received is the **backlog**: messages queued and not yet taken. The one being handled is already taken, so it does not count.

Kameo also exports `kameo_lifecycle_sent_total` and `kameo_link_died_sent_total`, which we leave out: kameo sends its own signals — startup, the stops a link triggers, every link-died notice — without counting them, so the sent side undercounts and link-died stays `0` forever. Only the received side is complete.

**Capacity** is ours: kameo exports none. `ActorHandle::new` records it from the mailbox itself (`ActorRef::mailbox_sender().max_capacity()`), so the dashboard never assumes a size. Every actor the service keeps a handle to is covered; the ones it keeps without one — the supervised executor, the channel signer and the stake config pubsub — are recorded with an explicit `record_mailbox_capacity` call where they are spawned. The Bedrock actors the sharding pool spawns per channel are recorded by the pool itself, through the hook `ShardingPoolActor::with_on_worker_spawned` calls with each new worker. An actor that is none of these shows **no data** for its capacity, never a made-up one — when adding one, give it a handle, that call, or a pool with that hook.

An unbounded mailbox exports infinity, which the exporter writes as Rust prints it, `inf`; Prometheus reads that as `+Inf`. In PromQL a backlog over `+Inf` is `0`, and `actor_mailbox_capacity < +Inf` keeps the bounded mailboxes only — what the dashboard's fill and capacity-line queries use, as Grafana cannot draw infinity.

Kameo only sees the mailbox: work an actor does inside its own `next()`, like the Bedrock actor's zone SDK events or the gossip actor's swarm events, is not in these counters.

### Handling time and lifecycle

Kameo traces every actor through `tracing`: each message's handler runs in an `actor.handle_message` span, and each run of an actor emits an `actor started` event and, at its end, `actor stopped` with the stop `reason`. A supervised restart is a new run of the same actor, so it shows up the same way. `actor_metrics.rs` in `sequencer_service` installs a tracing subscriber whose `ActorMetrics` layer turns these into the last three metrics above, for every actor, kameo_actors' included, with nothing to add at spawn sites:

- **Handling time** is the span's life: wall time, awaits included, during which the actor takes no other message. `rate()` of its `_sum` is the share of time the actor is busy. A handler that replies from a background task (`DelegatedReply`, as the executor's `GetBlockRange` does) counts only until it hands the work off.
- **State** follows the events: `running` on start; on stop `stopped` for `Normal` or `Killed`, `restarting` for `SupervisorRestart`, `failed` for `Panicked` (a panic, or an error from a handler or `on_start`) or `LinkDied`.
- **Start time** is set on every start. `changes()` over it counts restarts — by a supervisor or of the whole sequencer — even one quicker than a scrape, which would leave no gap in `actor_state`.
- **Sender** comes from the span the message was sent in, which kameo records as the handler span's `follows_from`: the type name of the actor whose code sent it (in a handler, in its `next()`, or in a span of ours that follows from a handler, like `GetBlockRange`'s background reads); outside any actor, the name of the outermost span, e.g. `rpc` for an RPC call; and `none` when it was sent in no span at all — the scheduler's timer, or setup code at startup.

A state shorter than a scrape (5 s) may not show at all: a sequencer whose actor fails exits soon after, often before Prometheus sees `failed`. The logs say why it stopped; kameo logs a panic as an error.

The same subscriber writes the logs and exports the [traces](#traces): its other layers are the `logging` crate's and `traces.rs`'s, filtered by `RUST_LOG`, while `ActorMetrics` takes kameo's spans and events at every level, and every other span at `info` or above, to tell who sent a message, whatever `RUST_LOG` says: so `sender` does not change with the log level.

## `dashboard_gen`

`tools/dashboard_gen` is a small Grafana dashboard builder plus the dashboard definitions. It prints JSON to stdout; the result is committed under `monitoring/grafana/dashboards/` and CI fails if it is stale.

```
src/lib.rs, schema.rs, styling.rs, unit.rs   the builder library
src/dashboards/<name>.rs                     one dashboard per module
src/main.rs                                  CLI: `dashboard_gen sequencer|network|actors|messages`
```

Panels are built fluently, and every query is composed from the `names` consts:

```rust
Panel::timeseries("Block production rate")
    .width(18)
    .target(rate_per_min(&seq(sequencer_core_metrics::names::BLOCKS_PRODUCED_TOTAL), "blocks/min"))
```

Query helpers: `rate_per_min` for counters, `avg` for histograms, and `selected_percentile` for percentile lines — the latter reads a `percentile` dashboard dropdown created by `percentile_variable`, so one panel serves p50/p90/p95/p99 instead of drawing all four; `selected_percentile_expr` is the same query over another window, e.g. `$__range` for one value per series over the whole time range. Rate windows use `$__rate_interval`, which tracks the panel's zoom.

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
| Which are slow, or saturated? | **All actors · handling time over the time range** at the **Percentile** dropdown's percentile, **All actors · busy** — near 100%, an actor cannot keep up |
| Is any mailbox filling up? | **All actors · fullest mailbox over the time range** — the highest backlog as a share of capacity; unbounded mailboxes have no fill and are left out |
| Is a backlog building? | **All actors · mailbox backlog**, and for the picked actor **mailbox backlog vs capacity**, its capacity drawn as a dashed line |
| Which actors ran, and when? | **All actors · lifecycle** — a timeline of running, stopped, restarting and failed, empty while an actor does not exist |
| Was anything restarted? | **All actors · restarts over the time range**, and the picked actor's **restarts** |
| How does the picked actor keep up? | **messages handled per second**, **busy**, **backlog**, **mailbox capacity** (`unbounded` for `+Inf`), **mailbox fill** (green, orange from 50%, red from 90%) |
| Which messages does the picked actor spend its time on? | **time spent per message over the time range**, **messages handled over the time range**, and over time **busy per message** and **messages handled per second** — stacked, so the messages add up to the actor's total |
| Which of its messages are slow? | **p95 handling time per message over the time range** (at the **Percentile** dropdown's percentile), **average handling time per message over the time range**, and over time **handling time per message** — solid at the percentile, dashed on average. Messages not handled in the window are left out |
| What did the picked actor go through? | **lifecycle**, and **lifecycle and link signals since startup** — kameo's own count of start and stop signals, and of deaths of actors linked to it |
| What did the picked actor log? | **warnings and errors**, linking to all its logs in Explore — the lines with its `actor` label, whichever crate logged them |
| Which of its messages are slow, judged by every message rather than by histogram buckets? Who keeps it busy, and what does it ask of others? | **p95 handling time per message, from traces** (at the **Percentile** dropdown's percentile), **handled per second by sender, from traces** and **sent per second, from traces**: `TraceQL` metrics over the [traces](#traces), e.g. `{ span.sequencer = "$sequencer" && span.actor = "$actor" } \| quantile_over_time(duration, $percentile) by (name)`. A click on a line offers the Messages dashboard for the same sequencer and actor over the minute centered on that point (`time` and `time.window` in its URL), whose tables list every message behind it, to sort by duration. On the panels by message, **These messages around this moment** also fills its **Message** field with the line's message, e.g. `ExecutorActor.ProduceBlock`; on the one by sender, **The messages around this moment** leaves it empty. The diamonds are exemplars, single messages; a click on one offers only its trace in Explore, as Grafana builds that link itself. They answer what the metric panels above do, but exactly and down to single messages, so they sit folded away in the last row, **… · from traces**, querying Tempo only once it is opened |
| Which messages exactly did the picked actor send and handle? | **messages sent** and **messages handled**: one row per message, the newest 200, from its traces; their header links to all of them on the Messages dashboard. A click on one opens it on the [Messages](#one-message-at-a-time) dashboard, selected, with the messages it sent in turn. **messages handled over the time range** links to that dashboard in its header too |
| Who sends messages to whom? | **All actors · who sends messages to whom over the time range** — a node graph: a circle per actor at the messages it handled per second, an arrow from each sender to the actors it sent to. Senders that are no actor, e.g. `rpc` or `none`, are circles too. Only what changed during the time range counts, so messages from before the first scrape, like most of startup's, do not show |

The node graph is `Panel::node_graph`, fed by two `Target::table` queries named `nodes` and `edges`: one row per series, with labels made into the `id`, `title`, `source` and `target` columns the panel reads. Its stat is the row's value, which a `calculateField` transformation copies into a field named `mainstat`, the only one the panel applies its unit to.

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

Our services log through `tracing`, and their images set `LOG_FORMAT=json`: each line is one JSON object holding a constant `message`, the event's fields (`block_id`, `tx_hash`, `error`, …) and under `span` the fields of every span it ran in, e.g. a kameo `actor.handle_message` span's or the cross-zone watcher's `peer_zone`; an inner span's field wins over an outer one's of the same name. While the service exports traces, the line also carries its trace and span ids under `openTelemetry`. Alloy takes the line's `timestamp` as the entry's and makes labels of its `level` and, on a sequencer's line, the `actor` it was logged in — the type name, e.g. `ExecutorActor`, as the actors dashboard names it. The trace and span ids become structured metadata, `trace_id` and `span_id`, and a line's details in Grafana offer **Show trace**. Alloy then cuts all these from the line, as Grafana shows them beside it anyway; `docker logs` still has them. The emitting module's `target` stays in the line rather than becoming a label: with a hundred or so values it would multiply Loki's streams. So a line reads `{"message":"Channel pin moved","pin":"91d4…","target":"sequencer_core"}`, `{sequencer="sequencer_0", actor="ExecutorActor"}` picks one actor's lines, and `| json | target="sequencer_core"` or `| json | block_id > 100` filters on any field.

The actor comes from kameo's `actor.lifecycle` and `actor.handle_message` spans, which the sequencer keeps in its JSON logs whatever `RUST_LOG` says of kameo (plain text leaves them out, as they would start every line with the actor's full type name). A line logged in neither — at startup, or in a task an actor spawned — has no `actor`. Grafana shows the fields of a JSON line under its details.

Read logs in **Explore** or **Drilldown → Logs**; the dashboards only point at them:

| Dashboard | Panel |
|---|---|
| Sequencer | **Warnings and errors** of the selected sequencer, with a header link to all its logs in Explore |
| Network | **Warnings per minute** and **Errors per minute** per sequencer, linking to them in Explore |

`dashboard_gen` builds log queries with `Target::logs`, a log list with `Panel::logs`, and Explore links with `explore_logs_url`. A natively run sequencer (`just run-sequencer`) is not in Docker, so its logs stay in the terminal.

## Traces

`--profile monitoring` also runs **Tempo**, Grafana's `tempo` datasource, its API on the host at `:3200`. A sequencer exports its spans over OTLP/HTTP to the collector `OTEL_EXPORTER_OTLP_ENDPOINT` names; the compose sequencers name Alloy's (`LEZ_COMPOSE_SEQUENCER_OTLP_ENDPOINT`, empty to turn it off), which forwards them to Tempo. A natively run one exports with `OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318 OTEL_RESOURCE_ATTRIBUTES=service.instance.id=sequencer_0 just run-sequencer`, named as Prometheus names it. Without the variable nothing is exported. The other standard `OTEL_*` variables apply: `OTEL_RESOURCE_ATTRIBUTES=service.instance.id=sequencer_0` names a compose node, as `sequencer` does in its metrics and logs, and `OTEL_TRACES_SAMPLER` can sample. A sequencer that cannot reach the collector warns once and drops the spans until it can. Config: `traces.rs` in `sequencer_service`, `monitoring/tempo/tempo.yml`.

What is exported is what `RUST_LOG` lets through, plus every span kameo opens for a handled message whatever it says of kameo. Each of those is the root of a trace of its own, named after the actor and the message — `ExecutorActor.ProduceBlock` — and **linked** to the span the message was sent in; the handler's own spans, its awaits and the lines it logs (as span events) are inside it. That one handled message is one trace is kameo's doing: it opens the span with no parent and records the sender as `follows_from`, which becomes the link. Spans that last as long as an actor (kameo's `actor.lifecycle`), an RPC connection (jsonrpsee's `connection`) or a watcher (`cross_zone_watcher`) are not exported: each would gather all that runs in it into one trace that never ends. What runs in them starts a trace of its own instead, under one of the spans opened where work comes in:

| Root span | What it is |
|---|---|
| `bedrock.blocks_processed`, `bedrock.turn_notification`, `bedrock.ready` | the Bedrock actor handling a zone SDK event, which it publishes to the executor through the broker |
| `bedrock.channel_message`, `bedrock.channel_read_up_to` | the Bedrock actor handling what it read following the channel's finalized history, which it publishes through the broker |
| `gossip.transaction`, `gossip.approval`, `gossip.config` | the gossip actor handling a message from a peer |
| `rpc.<method>`, e.g. `rpc.sendTransaction` | an RPC call; a batch is one `rpc.batch` |
| `cross_zone_pass` | one pass of a cross-zone watcher over its peer's channel |
| `sharding_pool_forward` | the sharding pool passing a message on to the worker for its key, e.g. the Bedrock actor for a channel, after its handler returned |
| `block_range_reads` | the executor reading a block range from storage, after its handler returned |
| `ExecutorActor.ProduceBlock` and others with no link | a message sent in no span: the scheduler's timer, or setup at startup |

A handled message's span carries attributes to search by, their names in `sequencer_service_metrics::traces`:

| Attribute | Value |
|---|---|
| `actor` | the actor that handled it, by type name, e.g. `ExecutorActor` |
| `sender` | what sent it: as the metrics' `sender` label, but by type name — `ExecutorActor`, `rpc`, or `none` |
| `cause` | the trace it was sent from, by name — `ExecutorActor.ProduceBlock`, `rpc.getBlock`, `bedrock.blocks_processed` — or the sender itself when that is no trace, e.g. an actor's own loop |
| `sequencer` | on every span: the sequencer's public key, as in its metrics. Alloy puts the node's `service.instance.id` in its place, `sequencer_0`…, as Prometheus and the logs name the nodes |

`sender` and `cause` are set by the actor metrics layer, which works the sender out anyway: once it has, it puts both on the handler's OpenTelemetry span (`traces::set_attributes`). `sequencer` is added on export, once the sequencer has loaded its key.

Read them in **Explore** with the Tempo datasource, **Drilldown → Traces**, or the [Messages](#one-message-at-a-time) dashboard. TraceQL finds them, e.g. `{ name = "ExecutorActor.ProduceBlock" && duration > 1s }`, `{ span.sender = "ExecutorActor" }` for the messages an actor sent, or `{ span.sequencer = "sequencer_1" }`. A span's details list its links, each opening the trace of what sent its message; the other way round, `{ link:traceID = "<trace id>" }` finds every message a trace sent. **Logs for this span** lists the lines logged in its trace.

### One message at a time

The **Messages** dashboard (`dashboards/messages.rs`) lists the messages one actor sent and handled, picked with the same **Sequencer** and **Actor** dropdowns as the Actors dashboard, newest first: all of them over the time range, up to the newest 10 000 each, counted under the table. The **Message** field keeps them to the messages whose name has its text in it, e.g. `ProduceBlock` (`name =~ ".*$message.*"`), all of them when empty; selecting a message keeps it. Their titles name that limit: a count reaching it means there are more, and narrowing the time range shows the older ones. Over an hour, the busiest actor has a few thousand; Tempo returns them in well under a second. A click on a message selects it: the top shows it, the messages it sent, and its trace on a timeline. A click on one of those selects that one; a click on what a message was **sent from** selects the message that sent it. So clicks go from message to message, down the cascade and back up. The selected message's trace id is in the **Selected message's trace** field, so a link to the dashboard with it filled in shares the selection.

| Panel | TraceQL |
|---|---|
| **Selected message** | `{ trace:id = "$trace" && nestedSetParent = -1 }`, the trace's root |
| **Messages it sent** | `{ link:traceID = "$trace" }` |
| **What the selected message did** | the trace `$trace`, in a row folded away until a click opens it: with no message selected, there is no trace to show, and the panel fails |
| **… · messages sent**, **… · messages handled** | `{ span.sequencer = "$sequencer" && span.sender = "$actor" }`, and `span.actor`. The Actors dashboard shows the same two tables, the newest 200 of each (`messages::newest_actor_messages`): it refreshes every 5 s. Its clicks open this one |

Each table query ends in `| select(span.sender, span.cause, link:traceID) with(most_recent=true)`: the selected columns, and the newest messages rather than any. `dashboard_gen` builds them with `Target::spans`, up to 200 traces unless `Target::limit` says otherwise, counted with `Panel::count_rows`, the timeline with `Panel::trace` and `Target::trace` in a `Dashboard::folded` row, followed by a `Dashboard::heading` so the tables below stay out of it, and the tables with `Panel::table`, laid out by `column`, `drop_columns` and `sort_descending` — by the column names Grafana gives, e.g. `Trace Name`, rather than the fields'. A click selects a message through a `FieldOverride::link` back to the dashboard, filling the `trace` text field (`textbox_variable`) with the row's `traceIdHidden`; the column of the trace a message was sent from, `link:traceID`, is renamed `sentFromTrace` for its link to name, and hidden. The Tempo datasource does not stream search results: a streamed search adds a progress frame, which a table shows as a second result to pick.

`TraceQL` metrics queries come from `Target::trace_metrics`, counted over a fixed `Target::step` of 30 s: Tempo picks a step of a few seconds otherwise, and Grafana fills in no `$__interval` in a step. Tempo names a series like `{name="ExecutorActor.ProduceBlock", p=0.95}`, which `Panel::rename_series` cuts down to `ExecutorActor.ProduceBlock`. Grafana draws a query's exemplars itself, with a **View trace** link to Explore; field overrides do not reach them, not even matched by their `Trace ID` column, so they cannot link to the Messages dashboard. A data link on the series can: `messages::around_point` opens it over a window centered on the clicked point's `${__value.time}`.

The dashboard does not refresh by itself, so the rows stay put while you click through them. A sequencer with no `service.instance.id` puts no `sequencer` on the messages it sends before it loads its key, so their earliest ones do not show in the actor's tables.

Where a cascade still breaks: the slasher's approvals and the channel signer's drafts reach the gossip actor through a channel, not a message, so they arrive with no sender; and a transaction waits in the mempool, which no message spans, so the `ProduceBlock` that includes it does not link to the `rpc.sendTransaction` that submitted it.

## Justfile

| Recipe | Purpose |
|---|---|
| `just regenerate-dashboards` | Rebuild the committed dashboard JSON. Run after touching metric names or dashboard code — CI checks it is current. |
| `just run-monitoring` | Prometheus (`:9090`), Loki (`:3100`) and Tempo (`:3200`) + Alloy, and Grafana (`:3000`, anonymous admin) in docker, scraping the sequencers every 5 s, collecting container logs and taking traces over OTLP on `:4318` |
| `just get-sequencer-metrics` | `curl` the raw `/metrics` endpoint — quickest way to confirm a metric name and value |
