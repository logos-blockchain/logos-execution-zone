//! A tiny, hand-rolled Grafana dashboard builder.
//!
//! This is a deliberately small subset of what the (Rust-less) Grafana
//! Foundation SDK does: model only the panel types and options we actually use,
//! expose a fluent builder, and render to the same dashboard JSON Grafana
//! provisions. The payoff over hand-written JSON:
//!
//! * metric names live in Rust `const`s, so a rename is a compile error here;
//! * repetitive structure (percentile targets, grid layout, legend/tooltip defaults) collapses into
//!   a single call instead of copy-pasted JSON.
//!
//! Build a [`Dashboard`] and serialize it directly.

// Styling vocabularies passed to the optional `styling` setters are part of the
// public API (and are used by this module's `Panel` fields and `finalize`).
use schema::{
    AlignValue, BarGaugeDisplay, BarGaugeOptions, BarGaugeSizing, BarGaugeValueMode, Calc,
    CalculateField, CalculateMode, CellHeight, Custom, CustomConfig, CustomVariable, DashboardLink,
    DashboardLinkKind, DashboardPanel, DataLink, Datasource, Defaults, DrawStyle, EmptyList,
    FieldConfig, Fill, GaugeOptions, GraphMode, GridPos, Legend, LegendDisplay, LineStyle,
    LogsOptions, LogsSortOrder, Matcher, MatcherKind, NamePlacement, NoOptions, NodeGraphOptions,
    NodeGraphStats, Options, Organize, Orientation, OverrideProperty, PanelLink, PanelModel,
    PanelType, Placement, PropertyId, PropertyValue, QueryType, QueryVariable, ReduceOptions,
    RenameByRegex, RowModel, RowReduce, ShowValue, SortOrder, Stacking, StatColorMode, StatOptions,
    StateTimelineOptions, StatusHistoryOptions, TableFooter, TableOptions, TableSort, TableType,
    TargetFormat, Templating, TextboxVariable, TimeRange, TimeSeriesOptions, TimelineCustom,
    Tooltip, TooltipMode, Transformation, ValueMapping, ValueMappingKind, ValueMappingResult,
    VariableHide, VariableOption, VariableRefresh, VariableSort, ZoomMode,
};
pub use schema::{
    AxisPlacement, Color, GradientMode, LineInterpolation, ShowPoints, StackingMode, Thresholds,
    Variable,
};
use serde::Serialize;
pub use unit::Unit;

mod schema;
mod styling;
mod unit;

/// Datasource uid every panel/target points at. Dashboards stay portable across
/// environments because they reference the datasource by this stable uid rather
/// than by a per-environment URL.
pub const DATASOURCE_UID: &str = "prometheus";

/// Datasource uid of the logs every [`Target::logs`] queries.
pub const LOGS_DATASOURCE_UID: &str = "loki";

/// Datasource uid of the traces every [`Target::spans`] and [`Target::trace`]
/// query.
pub const TRACES_DATASOURCE_UID: &str = "tempo";

/// Traces a [`Target::spans`] search returns at most.
const TRACES_LIMIT: u32 = 200;

/// Window every rate query — counter and histogram alike — rates over.
/// `$__rate_interval` tracks the panel's zoom, so the window always covers the
/// step Grafana samples at: a fixed one shorter than the step leaves gaps the
/// query never looks at, dropping events from the graph entirely.
const RATE_WINDOW: &str = "$__rate_interval";

/// Dashboard variable holding the quantile every percentile query reads.
const PERCENTILE_VAR: &str = "percentile";

/// Area fill under a timeseries line, as a percentage. Enough to read a series'
/// shape at a glance without drowning the ones stacked behind it.
pub(crate) const DEFAULT_FILL_OPACITY: u32 = 10;

/// Fill of a timeline panel's bars and cells: solid enough to read the color,
/// translucent enough to stay calm next to line charts.
const TIMELINE_FILL_OPACITY: u32 = 70;

/// Share of a timeline row (and status history column) its bars fill, leaving
/// a gap between neighbours.
const TIMELINE_ROW_HEIGHT: f64 = 0.9;

/// A metric name plus label matchers, rendered as a Prometheus selector:
/// `metric{label="value", …}`.
///
/// Query helpers take a `Selector` rather than a bare metric name, so a
/// dashboard scoped to one source (see [`label_values_variable`]) scopes every
/// series it reads.
#[derive(Clone)]
pub struct Selector {
    metric: String,
    /// Rendered matchers, e.g. `label="value"`.
    matchers: Vec<String>,
}

impl Selector {
    pub fn new(metric: impl Into<String>) -> Self {
        Self {
            metric: metric.into(),
            matchers: Vec::new(),
        }
    }

    /// Keep only series whose `label` equals `value`. `value` may reference a
    /// dashboard variable, e.g. `$sequencer`.
    #[must_use]
    pub fn label_eq(mut self, label: impl AsRef<str>, value: impl AsRef<str>) -> Self {
        self.matchers
            .push(format!("{}=\"{}\"", label.as_ref(), value.as_ref()));
        self
    }

    /// Keep only series whose whole `label` matches `regex`. `regex` may
    /// reference a dashboard variable.
    #[must_use]
    pub fn label_matches(mut self, label: impl AsRef<str>, regex: impl AsRef<str>) -> Self {
        self.matchers
            .push(format!("{}=~\"{}\"", label.as_ref(), regex.as_ref()));
        self
    }

    /// The selector for one of the series a histogram expands into, e.g.
    /// `_bucket`.
    fn suffixed(&self, suffix: &str) -> String {
        let matchers = self.matchers.join(", ");
        if matchers.is_empty() {
            format!("{}{suffix}", self.metric)
        } else {
            format!("{}{suffix}{{{matchers}}}", self.metric)
        }
    }
}

impl std::fmt::Display for Selector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.suffixed(""))
    }
}

/// A single query within a panel: of metrics or logs in `expr`, of traces in
/// `query`.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Target {
    datasource: Datasource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    format: Option<TargetFormat>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    instant: Option<bool>,
    #[serde(
        default,
        rename = "legendFormat",
        skip_serializing_if = "Option::is_none"
    )]
    legend: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    limit: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    query: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    query_type: Option<QueryType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    range: Option<bool>,
    ref_id: String,
    /// Spans shown per trace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    spss: Option<u32>,
    /// What a [`Target::trace_metrics`] counts each point over.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    step: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    table_type: Option<TableType>,
    /// Kept as the `ref_id`, which is otherwise the target's letter.
    #[serde(skip)]
    name: Option<String>,
    /// Whether it returns a series per value of some label, whatever its
    /// legend.
    #[serde(skip)]
    fans_out: bool,
}

impl Target {
    pub fn new(expr: impl Into<String>) -> Self {
        Self {
            datasource: Datasource::prometheus(),
            expr: Some(expr.into()),
            format: None,
            instant: None,
            legend: Some(String::new()),
            limit: None,
            query: None,
            query_type: None,
            range: None,
            ref_id: ref_letter(0),
            spss: None,
            step: None,
            table_type: None,
            name: None,
            fans_out: false,
        }
    }

    #[must_use]
    pub fn legend(mut self, legend: impl Into<String>) -> Self {
        self.legend = Some(legend.into());
        self
    }

    /// A `TraceQL` search, e.g. `{ span.actor = "$actor" }`, for a
    /// [`Panel::table`] of one row per span it matches, newest first, up to
    /// one per trace and 200 traces ([`Target::limit`] changes that). Grafana names the columns:
    /// `Trace Name`, `Start time` and `Duration`, the trace's id in `traceIdHidden`, and each
    /// attribute the query selects by its own name.
    pub fn spans(traceql: impl Into<String>) -> Self {
        Self {
            datasource: Datasource::tempo(),
            expr: None,
            legend: None,
            limit: Some(TRACES_LIMIT),
            query: Some(format!("{} with(most_recent=true)", traceql.into())),
            query_type: Some(QueryType::TraceQl),
            spss: Some(1),
            table_type: Some(TableType::Spans),
            ..Self::new(String::new())
        }
    }

    /// The trace whose id is `id`, e.g. `$trace`, for a [`Panel::trace`].
    pub fn trace(id: impl Into<String>) -> Self {
        Self {
            datasource: Datasource::tempo(),
            expr: None,
            legend: None,
            query: Some(id.into()),
            query_type: Some(QueryType::TraceQl),
            ..Self::new(String::new())
        }
    }

    /// A `TraceQL` metrics query, e.g. `{ span.actor = "$actor" } | rate()
    /// by (name)`, for a [`Panel::timeseries`]: a series per value of what
    /// it groups `by`, named like `{name="ExecutorActor.ProduceBlock"}`
    /// ([`Panel::rename_series`] cuts that down), with exemplars, the traces
    /// of some of the spans it counted, drawn as points.
    pub fn trace_metrics(traceql: impl Into<String>) -> Self {
        Self {
            fans_out: true,
            ..Self::trace(traceql)
        }
    }

    /// The most traces a [`Target::spans`] search returns, rather than 200.
    #[must_use]
    pub const fn limit(mut self, traces: u32) -> Self {
        self.limit = Some(traces);
        self
    }

    /// What a [`Target::trace_metrics`] counts each point over, e.g. `30s`,
    /// rather than the few seconds Tempo picks. A fixed duration: Grafana
    /// fills in no `$__interval` here.
    #[must_use]
    pub fn step(mut self, step: impl Into<String>) -> Self {
        self.step = Some(step.into());
        self
    }

    /// A query against the logs, e.g. `{sequencer="$sequencer"}` for a
    /// logs panel, or `count_over_time(…)` for a graph.
    pub fn logs(expr: impl Into<String>) -> Self {
        Self {
            datasource: Datasource::loki(),
            ..Self::new(expr)
        }
    }

    /// Evaluate once, at the end of the time range, instead of at every step.
    /// For panels that show one value per series, e.g. over `$__range`.
    #[must_use]
    pub const fn instant(mut self) -> Self {
        self.instant = Some(true);
        self.range = Some(false);
        self
    }

    /// Evaluate once into a table of one row per series, its labels in
    /// columns, named `name`: a [`Panel::node_graph`]'s `nodes` and `edges`.
    #[must_use]
    pub fn table(mut self, name: impl Into<String>) -> Self {
        self.format = Some(TargetFormat::Table);
        self.name = Some(name.into());
        self.instant()
    }
}

/// A per-series style override, matched by series name.
#[derive(Serialize)]
pub struct FieldOverride {
    matcher: Matcher,
    properties: Vec<OverrideProperty>,
}

impl FieldOverride {
    pub fn by_name(name: impl Into<String>) -> Self {
        Self {
            matcher: Matcher {
                id: MatcherKind::ByName,
                options: name.into(),
            },
            properties: Vec::new(),
        }
    }

    /// Matches every series whose name matches `regex`, e.g. `/ · avg$/`.
    pub fn by_regex(regex: impl Into<String>) -> Self {
        Self {
            matcher: Matcher {
                id: MatcherKind::ByRegexp,
                options: regex.into(),
            },
            properties: Vec::new(),
        }
    }

    #[must_use]
    pub fn color(mut self, color: Color) -> Self {
        self.properties.push(OverrideProperty {
            id: PropertyId::Color,
            value: PropertyValue::Color(color),
        });
        self
    }

    #[must_use]
    pub fn dashed_line(mut self) -> Self {
        self.properties.push(OverrideProperty {
            id: PropertyId::LineStyle,
            value: PropertyValue::LineStyle(LineStyle {
                dash: [8, 4],
                fill: Fill::Dash,
            }),
        });
        self
    }

    /// A link on every value; `url` may use Grafana's data link variables,
    /// e.g. `${__data.fields.traceIdHidden}` for another column of the row.
    #[must_use]
    pub fn link(mut self, title: impl Into<String>, url: impl Into<String>) -> Self {
        self.properties.push(OverrideProperty {
            id: PropertyId::Links,
            value: PropertyValue::Links(vec![DataLink {
                title: title.into(),
                url: url.into(),
            }]),
        });
        self
    }

    /// Keep a table's column out of view, its values still there for links.
    #[must_use]
    pub fn hidden(mut self) -> Self {
        self.properties.push(OverrideProperty {
            id: PropertyId::Hidden,
            value: PropertyValue::Flag(true),
        });
        self
    }

    /// The unit the matched values are shown in, e.g. a time format.
    #[must_use]
    pub fn unit(mut self, unit: Unit) -> Self {
        self.properties.push(OverrideProperty {
            id: PropertyId::Unit,
            value: PropertyValue::Unit(unit),
        });
        self
    }

    /// A table column's width, in pixels.
    #[must_use]
    pub fn width(mut self, pixels: u32) -> Self {
        self.properties.push(OverrideProperty {
            id: PropertyId::Width,
            value: PropertyValue::Pixels(pixels),
        });
        self
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Stat,
    TimeSeries,
    Gauge,
    BarGauge,
    Logs,
    StateTimeline,
    StatusHistory,
    NodeGraph,
    Table,
    Trace,
}

/// A dashboard panel builder. Grid position and panel id are assigned by
/// [`Dashboard::row`]; everything else is set here.
pub struct Panel {
    title: String,
    description: Option<String>,
    kind: Kind,
    targets: Vec<Target>,
    width: u32,
    unit: Option<Unit>,
    decimals: Option<u32>,
    color: Option<Color>,
    min: Option<f64>,
    max: Option<f64>,
    thresholds: Option<Thresholds>,
    span_nulls: bool,
    overrides: Vec<FieldOverride>,
    mappings: Vec<(String, String, String)>,
    links: Vec<DataLink>,
    header_links: Vec<PanelLink>,
    min_interval: Option<String>,
    max_data_points: Option<u32>,
    // Optional timeseries styling, set via the `styling` setters.
    fill_opacity: Option<u32>,
    line_interpolation: Option<LineInterpolation>,
    show_points: Option<ShowPoints>,
    gradient_mode: Option<GradientMode>,
    stacking: Option<StackingMode>,
    axis_placement: Option<AxisPlacement>,
    axis_label: Option<String>,
    /// Series renames, as `(regex, pattern)`.
    renames: Vec<(String, String)>,
    // Table layout, set via the column setters.
    columns: Vec<(String, String)>,
    dropped_columns: Vec<String>,
    sorted_by: Option<String>,
    rows_counted: bool,
}

impl Panel {
    fn new(title: impl Into<String>, kind: Kind) -> Self {
        Self {
            title: title.into(),
            description: None,
            kind,
            targets: Vec::new(),
            width: 0,
            unit: None,
            decimals: None,
            color: None,
            min: None,
            max: None,
            thresholds: None,
            span_nulls: false,
            overrides: Vec::new(),
            mappings: Vec::new(),
            links: Vec::new(),
            header_links: Vec::new(),
            min_interval: None,
            max_data_points: None,
            fill_opacity: None,
            line_interpolation: None,
            show_points: None,
            gradient_mode: None,
            stacking: None,
            axis_placement: None,
            axis_label: None,
            renames: Vec::new(),
            columns: Vec::new(),
            dropped_columns: Vec::new(),
            sorted_by: None,
            rows_counted: false,
        }
    }

    /// A single big-number panel.
    pub fn stat(title: impl Into<String>) -> Self {
        Self::new(title, Kind::Stat)
    }

    /// A time-series line panel.
    pub fn timeseries(title: impl Into<String>) -> Self {
        Self::new(title, Kind::TimeSeries)
    }

    /// A radial gauge panel. Pair it with [`Panel::min`]/[`Panel::max`] — the
    /// dial needs a range to fill — and [`Panel::thresholds`] for its coloring.
    pub fn gauge(title: impl Into<String>) -> Self {
        Self::new(title, Kind::Gauge)
    }

    /// One horizontal bar per series, e.g. to compare shares.
    pub fn bar_gauge(title: impl Into<String>) -> Self {
        Self::new(title, Kind::BarGauge)
    }

    /// One row per series, a bar wherever the value holds. Pair it with
    /// [`Panel::value_mapping`] to name and color the states.
    pub fn state_timeline(title: impl Into<String>) -> Self {
        Self::new(title, Kind::StateTimeline)
    }

    /// Log lines, newest first. Pair it with [`Target::logs`].
    pub fn logs(title: impl Into<String>) -> Self {
        Self::new(title, Kind::Logs)
    }

    /// One row per series, a cell per query step colored by its value: a
    /// heatmap of series over time.
    pub fn status_history(title: impl Into<String>) -> Self {
        Self::new(title, Kind::StatusHistory)
    }

    /// Nodes and the edges between them, from a `nodes` and an `edges`
    /// [`Target::table`]. Their rows need an `id`, a node's also a `title` to
    /// show and an edge's a `source` and a `target` node id. Their value is the
    /// stat shown, in the panel's [`Panel::unit`].
    pub fn node_graph(title: impl Into<String>) -> Self {
        Self::new(title, Kind::NodeGraph)
    }

    /// The rows of a query's result, its fields in columns, e.g. a
    /// [`Target::spans`]. Lay them out with [`Panel::column`],
    /// [`Panel::drop_columns`] and [`Panel::sort_descending`].
    pub fn table(title: impl Into<String>) -> Self {
        Self::new(title, Kind::Table)
    }

    /// The spans of one trace on a timeline, from a [`Target::trace`].
    pub fn trace(title: impl Into<String>) -> Self {
        Self::new(title, Kind::Trace)
    }

    /// Show a table's column `name`, as Grafana names it, titled `title`. The
    /// columns named this way come first, in the order named. A
    /// [`FieldOverride`] matches the column by `title`.
    #[must_use]
    pub fn column(mut self, name: impl Into<String>, title: impl Into<String>) -> Self {
        self.columns.push((name.into(), title.into()));
        self
    }

    /// Leave a table's columns `names`, as Grafana names them, out.
    #[must_use]
    pub fn drop_columns(mut self, names: &[&str]) -> Self {
        self.dropped_columns
            .extend(names.iter().map(|&name| name.to_owned()));
        self
    }

    /// Count a table's rows, under them.
    #[must_use]
    pub const fn count_rows(mut self) -> Self {
        self.rows_counted = true;
        self
    }

    /// Sort a table by its column `title`, largest first.
    #[must_use]
    pub fn sort_descending(mut self, title: impl Into<String>) -> Self {
        self.sorted_by = Some(title.into());
        self
    }

    /// Rename the series whose names match `regex` to `pattern`, which may use
    /// its capture groups, e.g. `$1`.
    #[must_use]
    pub fn rename_series(mut self, regex: impl Into<String>, pattern: impl Into<String>) -> Self {
        self.renames.push((regex.into(), pattern.into()));
        self
    }

    /// Shown behind the `i` next to the title.
    #[must_use]
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Show `value` as `text` in `color`.
    #[must_use]
    pub fn value_mapping(
        mut self,
        value: impl Into<String>,
        text: impl Into<String>,
        color: impl Into<String>,
    ) -> Self {
        self.mappings
            .push((value.into(), text.into(), color.into()));
        self
    }

    /// A link on every value; `url` may use Grafana's data link variables,
    /// e.g. `${__field.labels.sequencer}`.
    #[must_use]
    pub fn link(mut self, title: impl Into<String>, url: impl Into<String>) -> Self {
        self.links.push(DataLink {
            title: title.into(),
            url: url.into(),
        });
        self
    }

    /// A link in the panel's header, e.g. to [`explore_logs_url`]. `url` may use
    /// dashboard variables.
    #[must_use]
    pub fn header_link(mut self, title: impl Into<String>, url: impl Into<String>) -> Self {
        self.header_links.push(PanelLink {
            target_blank: false,
            title: title.into(),
            url: url.into(),
        });
        self
    }

    /// Lower bound on the query step (`$__interval`), e.g. `"1m"`.
    #[must_use]
    pub fn min_interval(mut self, interval: impl Into<String>) -> Self {
        self.min_interval = Some(interval.into());
        self
    }

    /// Upper bound on the points per series, so the step grows with the range
    /// rather than with the panel's width.
    #[must_use]
    pub const fn max_data_points(mut self, points: u32) -> Self {
        self.max_data_points = Some(points);
        self
    }

    /// Grid width in Grafana's 24-column units. Unset panels split the row's
    /// remaining width evenly.
    #[must_use]
    pub const fn width(mut self, width: u32) -> Self {
        self.width = width;
        self
    }

    #[must_use]
    pub fn unit(mut self, unit: Unit) -> Self {
        self.unit = Some(unit);
        self
    }

    #[must_use]
    pub const fn decimals(mut self, decimals: u32) -> Self {
        self.decimals = Some(decimals);
        self
    }

    #[must_use]
    pub fn color(mut self, color: Color) -> Self {
        self.color = Some(color);
        self
    }

    /// Lower bound of the value scale.
    #[must_use]
    pub const fn min(mut self, min: f64) -> Self {
        self.min = Some(min);
        self
    }

    /// Upper bound of the value scale.
    #[must_use]
    pub const fn max(mut self, max: f64) -> Self {
        self.max = Some(max);
        self
    }

    #[must_use]
    pub fn thresholds(mut self, thresholds: Thresholds) -> Self {
        self.thresholds = Some(thresholds);
        self
    }

    #[must_use]
    pub const fn span_nulls(mut self) -> Self {
        self.span_nulls = true;
        self
    }

    #[must_use]
    pub fn target(mut self, target: Target) -> Self {
        self.targets.push(target);
        self
    }

    #[must_use]
    pub fn targets(mut self, targets: impl IntoIterator<Item = Target>) -> Self {
        self.targets.extend(targets);
        self
    }

    #[must_use]
    pub fn with_override(mut self, over: FieldOverride) -> Self {
        self.overrides.push(over);
        self
    }

    fn finalize(self, id: u32, grid_pos: GridPos) -> PanelModel {
        let targets: Vec<Target> = self
            .targets
            .into_iter()
            .enumerate()
            .map(|(i, mut t)| {
                t.ref_id = t.name.clone().unwrap_or_else(|| ref_letter(i));
                t
            })
            .collect();

        let unit = self.unit.unwrap_or_else(default_unit);
        // A node graph reads its stat off a field named `mainstat`, and only to
        // that one applies its unit.
        let renames = self.renames.into_iter().map(|(regex, rename_pattern)| {
            Transformation::RenameByRegex(RenameByRegex {
                regex,
                rename_pattern,
            })
        });
        let mut transformations = match self.kind {
            Kind::NodeGraph => vec![Transformation::CalculateField(CalculateField {
                alias: "mainstat".to_owned(),
                mode: CalculateMode::ReduceRow,
                reduce: RowReduce { reducer: Calc::Sum },
                replace_fields: false,
                time_series: false,
            })],
            Kind::Table if !(self.columns.is_empty() && self.dropped_columns.is_empty()) => {
                vec![Transformation::Organize(organize(
                    self.columns,
                    self.dropped_columns,
                ))]
            }
            Kind::Stat
            | Kind::TimeSeries
            | Kind::Gauge
            | Kind::BarGauge
            | Kind::Logs
            | Kind::StateTimeline
            | Kind::StatusHistory
            | Kind::Table
            | Kind::Trace => Vec::new(),
        };
        transformations.extend(renames);
        let (defaults, options, panel_type) = match self.kind {
            Kind::Stat => {
                let defaults = Defaults {
                    color: self.color,
                    custom: None,
                    unit: Some(unit),
                    decimals: self.decimals,
                    min: self.min,
                    max: self.max,
                    thresholds: self.thresholds,
                    mappings: Vec::new(),
                    links: Vec::new(),
                };
                let options = Options::Stat(StatOptions {
                    color_mode: StatColorMode::Value,
                    graph_mode: GraphMode::Area,
                    reduce_options: ReduceOptions {
                        calcs: vec![Calc::LastNotNull],
                        fields: String::new(),
                        values: false,
                    },
                });
                (defaults, options, PanelType::Stat)
            }
            Kind::Gauge => {
                let defaults = Defaults {
                    color: self.color,
                    custom: None,
                    unit: Some(unit),
                    decimals: self.decimals,
                    min: self.min,
                    max: self.max,
                    thresholds: self.thresholds,
                    mappings: Vec::new(),
                    links: Vec::new(),
                };
                let options = Options::Gauge(GaugeOptions {
                    reduce_options: ReduceOptions {
                        calcs: vec![Calc::LastNotNull],
                        fields: String::new(),
                        values: false,
                    },
                    show_threshold_labels: false,
                    show_threshold_markers: true,
                });
                (defaults, options, PanelType::Gauge)
            }
            Kind::TimeSeries => {
                let defaults = Defaults {
                    color: self.color,
                    custom: Some(CustomConfig::TimeSeries(Custom {
                        draw_style: DrawStyle::Line,
                        line_width: 1,
                        fill_opacity: self.fill_opacity.unwrap_or(DEFAULT_FILL_OPACITY),
                        span_nulls: self.span_nulls.then_some(true),
                        line_interpolation: self.line_interpolation,
                        show_points: self.show_points,
                        gradient_mode: self.gradient_mode,
                        stacking: self.stacking.map(|mode| Stacking {
                            mode,
                            group: "A".to_owned(),
                        }),
                        axis_placement: self.axis_placement,
                        axis_label: self.axis_label,
                    })),
                    unit: Some(unit),
                    decimals: None,
                    min: self.min,
                    max: self.max,
                    thresholds: self.thresholds,
                    mappings: Vec::new(),
                    links: Vec::new(),
                };
                // Panels with several series read better as a sortable table with
                // a multi-series tooltip; single-series panels stay compact. A
                // `{{label}}` legend fans one target out into a series per label
                // value, so it counts as several too.
                let multi = targets.len() > 1
                    || targets.iter().any(|target| {
                        target.fans_out
                            || target
                                .legend
                                .as_deref()
                                .is_some_and(|legend| legend.contains("{{"))
                    });
                let options = Options::TimeSeries(TimeSeriesOptions {
                    legend: Legend {
                        display_mode: if multi {
                            LegendDisplay::Table
                        } else {
                            LegendDisplay::List
                        },
                        placement: Placement::Bottom,
                        calcs: vec![Calc::Last, Calc::Max],
                        shown: None,
                    },
                    tooltip: if multi {
                        Tooltip {
                            mode: TooltipMode::Multi,
                            sort: Some(SortOrder::Desc),
                        }
                    } else {
                        Tooltip {
                            mode: TooltipMode::Single,
                            sort: None,
                        }
                    },
                });
                (defaults, options, PanelType::Timeseries)
            }
            Kind::BarGauge => {
                let defaults = Defaults {
                    color: self.color,
                    custom: None,
                    unit: Some(unit),
                    decimals: self.decimals,
                    min: self.min,
                    max: self.max,
                    thresholds: self.thresholds,
                    mappings: Vec::new(),
                    links: Vec::new(),
                };
                let options = Options::BarGauge(BarGaugeOptions {
                    display_mode: BarGaugeDisplay::Basic,
                    // Grafana's defaults, but for the minimum height: at its
                    // 16px, crowded bars leave no room for the name above.
                    max_viz_height: 300,
                    min_viz_height: 36,
                    min_viz_width: 8,
                    name_placement: NamePlacement::Top,
                    orientation: Orientation::Horizontal,
                    reduce_options: ReduceOptions {
                        calcs: vec![Calc::LastNotNull],
                        fields: String::new(),
                        values: false,
                    },
                    show_unfilled: true,
                    sizing: BarGaugeSizing::Manual,
                    value_mode: BarGaugeValueMode::Text,
                });
                (defaults, options, PanelType::BarGauge)
            }
            Kind::NodeGraph => {
                let defaults = Defaults {
                    color: None,
                    custom: None,
                    unit: Some(unit.clone()),
                    decimals: self.decimals,
                    min: None,
                    max: None,
                    thresholds: None,
                    mappings: Vec::new(),
                    links: Vec::new(),
                };
                let options = Options::NodeGraph(NodeGraphOptions {
                    edges: NodeGraphStats {
                        main_stat_unit: unit.clone(),
                    },
                    nodes: NodeGraphStats {
                        main_stat_unit: unit,
                    },
                    zoom_mode: ZoomMode::Cooperative,
                });
                (defaults, options, PanelType::NodeGraph)
            }
            Kind::Table => {
                let options = Options::Table(TableOptions {
                    cell_height: CellHeight::Sm,
                    footer: self.rows_counted.then(|| TableFooter {
                        count_rows: true,
                        fields: String::new(),
                        reducer: vec![Calc::Count],
                        show: true,
                    }),
                    show_header: true,
                    sort_by: self
                        .sorted_by
                        .into_iter()
                        .map(|display_name| TableSort {
                            desc: true,
                            display_name,
                        })
                        .collect(),
                });
                (Defaults::empty(), options, PanelType::Table)
            }
            Kind::Trace => (
                Defaults::empty(),
                Options::None(NoOptions {}),
                PanelType::Traces,
            ),
            Kind::Logs => {
                let defaults = Defaults {
                    color: None,
                    custom: None,
                    unit: Some(unit),
                    decimals: None,
                    min: None,
                    max: None,
                    thresholds: None,
                    mappings: Vec::new(),
                    links: Vec::new(),
                };
                let options = Options::Logs(LogsOptions {
                    enable_log_details: true,
                    show_time: true,
                    sort_order: LogsSortOrder::Descending,
                    wrap_log_message: true,
                });
                (defaults, options, PanelType::Logs)
            }
            Kind::StateTimeline | Kind::StatusHistory => {
                let defaults = Defaults {
                    color: self.color,
                    custom: Some(CustomConfig::Timeline(TimelineCustom {
                        line_width: 0,
                        fill_opacity: self.fill_opacity.unwrap_or(TIMELINE_FILL_OPACITY),
                    })),
                    unit: Some(unit),
                    decimals: self.decimals,
                    min: self.min,
                    max: self.max,
                    thresholds: self.thresholds,
                    mappings: Vec::new(),
                    links: Vec::new(),
                };
                let tooltip = Tooltip {
                    mode: TooltipMode::Single,
                    sort: None,
                };
                // A mapped state names itself in the legend; a color scale
                // has nothing to list.
                let legend = Legend {
                    display_mode: LegendDisplay::List,
                    placement: Placement::Bottom,
                    calcs: Vec::new(),
                    shown: self.mappings.is_empty().then_some(false),
                };
                if matches!(self.kind, Kind::StateTimeline) {
                    let options = Options::StateTimeline(StateTimelineOptions {
                        align_value: AlignValue::Left,
                        legend,
                        merge_values: true,
                        row_height: TIMELINE_ROW_HEIGHT,
                        show_value: ShowValue::Never,
                        tooltip,
                    });
                    (defaults, options, PanelType::StateTimeline)
                } else {
                    let options = Options::StatusHistory(StatusHistoryOptions {
                        col_width: TIMELINE_ROW_HEIGHT,
                        legend,
                        row_height: TIMELINE_ROW_HEIGHT,
                        show_value: ShowValue::Auto,
                        tooltip,
                    });
                    (defaults, options, PanelType::StatusHistory)
                }
            }
        };
        let defaults = Defaults {
            mappings: value_mappings(self.mappings),
            links: self.links,
            ..defaults
        };

        PanelModel {
            // A panel queries one datasource, so its queries pick it.
            datasource: targets
                .first()
                .map_or_else(Datasource::prometheus, |target| target.datasource.clone()),
            description: self.description,
            field_config: FieldConfig {
                defaults,
                overrides: self.overrides,
            },
            grid_pos,
            id,
            interval: self.min_interval,
            links: self.header_links,
            max_data_points: self.max_data_points,
            options,
            targets,
            title: self.title,
            transformations,
            panel_type,
        }
    }
}

/// A dashboard, built row by row. Serialize it directly to get the JSON.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Dashboard {
    annotations: EmptyList,
    editable: bool,
    graph_tooltip: u32,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    links: Vec<DashboardLink>,
    panels: Vec<DashboardPanel>,
    refresh: String,
    schema_version: u32,
    tags: Vec<String>,
    templating: Templating,
    time: TimeRange,
    timezone: String,
    title: String,
    uid: String,

    // Layout cursor — not part of the dashboard schema.
    #[serde(skip)]
    next_id: u32,
    #[serde(skip)]
    cursor_y: u32,
}

impl Dashboard {
    pub fn new(title: impl Into<String>, uid: impl Into<String>) -> Self {
        Self {
            annotations: EmptyList::default(),
            editable: true,
            graph_tooltip: 1,
            links: Vec::new(),
            panels: Vec::new(),
            refresh: "5s".to_owned(),
            schema_version: 39,
            tags: Vec::new(),
            templating: Templating::default(),
            time: TimeRange {
                from: "now-15m".to_owned(),
                to: "now".to_owned(),
            },
            timezone: String::new(),
            title: title.into(),
            uid: uid.into(),
            next_id: 1,
            cursor_y: 0,
        }
    }

    #[must_use]
    pub fn tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    #[must_use]
    pub fn refresh(mut self, refresh: impl Into<String>) -> Self {
        self.refresh = refresh.into();
        self
    }

    /// Add a top-bar link to every dashboard tagged `tag`, keeping the time
    /// range.
    #[must_use]
    pub fn link_tagged(mut self, title: impl Into<String>, tag: impl Into<String>) -> Self {
        self.links.push(DashboardLink {
            as_dropdown: false,
            include_vars: false,
            keep_time: true,
            tags: vec![tag.into()],
            title: title.into(),
            kind: DashboardLinkKind::Dashboards,
        });
        self
    }

    /// Add a dropdown to the dashboard's top bar, e.g. [`percentile_variable`].
    #[must_use]
    pub fn variable(mut self, variable: Variable) -> Self {
        self.templating.list.push(variable);
        self
    }

    /// Place a horizontal row of panels at the current vertical cursor. Panel
    /// ids, x offsets and y are assigned here; unset widths split the remaining
    /// 24 columns evenly.
    #[must_use]
    pub fn row(mut self, height: u32, panels: impl IntoIterator<Item = Panel>) -> Self {
        let placed = self.place(height, self.cursor_y, panels);
        self.panels.extend(
            placed
                .into_iter()
                .map(|panel| DashboardPanel::Panel(Box::new(panel))),
        );
        self.cursor_y = self.cursor_y.saturating_add(height);
        self
    }

    /// A row heading titled `title`, over the panels placed after it up to the
    /// next one, which a click on it folds away.
    #[must_use]
    pub fn heading(mut self, title: impl Into<String>) -> Self {
        let row = self.row_model(title.into(), false, Vec::new());
        self.panels.push(DashboardPanel::Row(row));
        self
    }

    /// A row of `panels`, `height` high, folded away under a heading titled
    /// `title`: they run no queries until a click opens it. Once it is open,
    /// the panels after it up to the next heading fold away with it too, so
    /// follow it with a [`Dashboard::heading`] unless it comes last.
    #[must_use]
    pub fn folded(
        mut self,
        title: impl Into<String>,
        height: u32,
        panels: impl IntoIterator<Item = Panel>,
    ) -> Self {
        let placed = self.place(height, self.cursor_y.saturating_add(1), panels);
        let row = self.row_model(title.into(), true, placed);
        self.panels.push(DashboardPanel::Row(row));
        self
    }

    /// A heading one unit high at the cursor, which it moves past.
    const fn row_model(
        &mut self,
        title: String,
        collapsed: bool,
        panels: Vec<PanelModel>,
    ) -> RowModel {
        let row = RowModel {
            collapsed,
            grid_pos: GridPos {
                h: 1,
                w: 24,
                x: 0,
                y: self.cursor_y,
            },
            id: self.next_id,
            panels,
            title,
            panel_type: PanelType::Row,
        };
        self.next_id = self.next_id.saturating_add(1);
        self.cursor_y = self.cursor_y.saturating_add(1);
        row
    }

    /// `panels` side by side at `y`, `height` high, with their ids.
    fn place(
        &mut self,
        height: u32,
        y: u32,
        panels: impl IntoIterator<Item = Panel>,
    ) -> Vec<PanelModel> {
        let panels: Vec<Panel> = panels.into_iter().collect();
        let specified: u32 = panels.iter().map(|p| p.width).sum();
        let auto_count = u32::try_from(panels.iter().filter(|p| p.width == 0).count()).unwrap_or(0);
        // `checked_div` yields `None` when there are no auto-width panels; the
        // fallback width is unused in that case.
        let auto_width = 24_u32
            .saturating_sub(specified)
            .checked_div(auto_count)
            .unwrap_or(0);

        let mut x = 0;
        let mut placed = Vec::new();
        for panel in panels {
            let w = if panel.width == 0 {
                auto_width
            } else {
                panel.width
            };
            let grid_pos = GridPos { h: height, w, x, y };
            let id = self.next_id;
            self.next_id = self.next_id.saturating_add(1);
            x = x.saturating_add(w);
            placed.push(panel.finalize(id, grid_pos));
        }
        placed
    }
}

impl Variable {
    /// Cut each fetched choice down to the first capture group of `regex`, a
    /// JavaScript regex with its slashes, e.g. `/^(\w+)/`. The cut is both what
    /// the dropdown shows and what `$name` holds, unless the groups named `text`
    /// and `value` set them apart: `${name:text}` holds the shown one.
    ///
    /// Panics on a variable whose choices are not fetched.
    #[must_use]
    pub fn regex(mut self, regex: impl Into<String>) -> Self {
        match &mut self {
            Self::Query(variable) => variable.regex = Some(regex.into()),
            Self::Custom(_) => {
                panic!("a custom variable spells out its choices: no regex to cut them with")
            }
            Self::Textbox(_) => panic!("a text field has no choices to cut"),
        }
        self
    }

    /// Leave the variable out of the top bar, for one the dashboard derives
    /// from the others, e.g. through [`Variable::regex`].
    ///
    /// Panics on a variable whose choices are not fetched.
    #[must_use]
    pub fn hidden(mut self) -> Self {
        match &mut self {
            Self::Query(variable) => variable.hide = Some(VariableHide::Variable),
            Self::Custom(_) => panic!("a custom variable is there to be picked from"),
            Self::Textbox(_) => panic!("a text field is there to be filled in"),
        }
        self
    }
}

/// The dropdown driving every [`selected_percentile`] query, offering
/// `percentiles` (e.g. `[50, 90, 95, 99]`) with `default` pre-selected.
///
/// Panics if `default` is not one of `percentiles`, or if any of them falls
/// outside `p1..=p99`.
#[must_use]
pub fn percentile_variable(percentiles: &[u32], default: u32) -> Variable {
    assert!(
        percentiles.contains(&default),
        "default p{default} is not one of the offered percentiles {percentiles:?}",
    );

    let options: Vec<VariableOption> = percentiles
        .iter()
        .map(|&p| VariableOption {
            selected: p == default,
            text: format!("p{p}"),
            value: quantile(p),
        })
        .collect();
    let current = options
        .iter()
        .find(|option| option.selected)
        .cloned()
        .expect("`default` is one of `percentiles`, asserted above");
    let query = options
        .iter()
        .map(|option| format!("{} : {}", option.text, option.value))
        .collect::<Vec<_>>()
        .join(", ");

    Variable::Custom(CustomVariable {
        current,
        include_all: false,
        label: "Percentile".to_owned(),
        // A quantile is a scalar argument to `histogram_quantile`, so exactly
        // one may be selected.
        multi: false,
        name: PERCENTILE_VAR.to_owned(),
        options,
        query,
    })
}

/// A text field named `name` (referenced as `$name`), titled `title`, starting
/// empty: for a value links fill in, e.g. the trace a click picked.
#[must_use]
pub fn textbox_variable(name: &str, title: &str) -> Variable {
    Variable::Textbox(TextboxVariable {
        label: title.to_owned(),
        name: name.to_owned(),
        query: String::new(),
    })
}

/// A single-choice dropdown named `name` (referenced as `$name`), titled
/// `title`, offering every value `label` takes across `metric`'s series.
#[must_use]
pub fn label_values_variable(name: &str, title: &str, metric: &str, label: &str) -> Variable {
    let query = format!("label_values({metric}, {label})");
    Variable::Query(QueryVariable {
        datasource: Datasource::prometheus(),
        definition: query.clone(),
        hide: None,
        include_all: false,
        label: title.to_owned(),
        multi: false,
        name: name.to_owned(),
        query,
        refresh: VariableRefresh::OnTimeRangeChange,
        regex: None,
        sort: VariableSort::NaturalAsc,
    })
}

/// A single-choice dropdown named `name` (referenced as `$name`), titled
/// `title`, offering a choice per series of the instant query `expr`.
///
/// Each is the series as it prints, e.g. `{key="a"} 1 1700000000000`, for
/// [`Variable::regex`] to cut.
#[must_use]
pub fn query_result_variable(name: &str, title: &str, expr: &str) -> Variable {
    let query = format!("query_result({expr})");
    Variable::Query(QueryVariable {
        datasource: Datasource::prometheus(),
        definition: query.clone(),
        hide: None,
        include_all: false,
        label: title.to_owned(),
        multi: false,
        name: name.to_owned(),
        query,
        refresh: VariableRefresh::OnTimeRangeChange,
        regex: None,
        sort: VariableSort::NaturalAsc,
    })
}

/// The quantile the [`percentile_variable`] dropdown holds, e.g. `0.95`, for
/// queries other than [`selected_percentile`]'s.
#[must_use]
pub fn selected_quantile() -> String {
    format!("${PERCENTILE_VAR}")
}

/// The legend fragment that renders the dropdown's current choice, e.g. `p95`.
#[must_use]
pub fn percentile_legend() -> String {
    format!("${{{PERCENTILE_VAR}:text}}")
}

/// A [`histogram_quantile`] line over `metric`'s buckets, at whatever quantile
/// [`percentile_variable`] currently holds. `labels` stay split out into their
/// own series; every other label is summed away.
///
/// [`histogram_quantile`]: https://prometheus.io/docs/prometheus/latest/querying/functions/#histogram_quantile
#[must_use]
pub fn selected_percentile(metric: &Selector, labels: &[&str], legend: &str) -> Target {
    Target::new(selected_percentile_expr(metric, labels, RATE_WINDOW)).legend(legend)
}

/// [`selected_percentile`]'s query, over `window` instead, e.g. `$__range`
/// for one value per series over the whole time range.
#[must_use]
pub fn selected_percentile_expr(metric: &Selector, labels: &[&str], window: &str) -> String {
    // `le` carries the bucket boundary, so it must survive the aggregation.
    let grouping = std::iter::once("le")
        .chain(labels.iter().copied())
        .collect::<Vec<_>>()
        .join(", ");

    let buckets = metric.suffixed("_bucket");
    format!(
        "histogram_quantile(${{{PERCENTILE_VAR}}}, sum by ({grouping}) (rate({buckets}[{window}])))"
    )
}

/// A percentile as its `histogram_quantile` argument, derived without float
/// math: zero-pad to two digits then drop trailing zeros (50 → `0.5`).
///
/// Panics outside `1..=99`, the only range two digits render: p100 would come
/// out as `0.1` and p0 as `0.`, neither of them loudly.
fn quantile(percentile: u32) -> String {
    assert!(
        (1..=99).contains(&percentile),
        "p{percentile} is outside the supported range p1..=p99",
    );

    let quantile = format!("0.{percentile:02}");
    quantile.trim_end_matches('0').to_owned()
}

/// An `avg` target for a histogram metric: `rate(sum) / rate(count)`.
#[must_use]
pub fn avg(metric: &Selector) -> Target {
    let sum = metric.suffixed("_sum");
    let count = metric.suffixed("_count");
    Target::new(format!(
        "rate({sum}[{RATE_WINDOW}]) / rate({count}[{RATE_WINDOW}])"
    ))
    .legend("avg")
}

/// A per-minute rate target for a counter metric.
#[must_use]
pub fn rate_per_min(metric: &Selector, legend: &str) -> Target {
    //`rate` is per-second whatever the window, so `* 60` is per-minute regardless of the panel's
    //`rate` zoom.
    Target::new(format!("rate({metric}[{RATE_WINDOW}]) * 60")).legend(legend)
}

/// A table's [`Panel::column`]s and [`Panel::drop_columns`] as Grafana's
/// `organize` step.
fn organize(columns: Vec<(String, String)>, dropped: Vec<String>) -> Organize {
    let mut organize = Organize::default();
    for ((name, title), index) in columns.into_iter().zip(0_u32..) {
        organize.index_by_name.insert(name.clone(), index);
        if title != name {
            organize.rename_by_name.insert(name, title);
        }
    }
    organize.exclude_by_name = dropped.into_iter().map(|name| (name, true)).collect();
    organize
}

/// [`Panel::value_mapping`]s as Grafana's single `value` mapping.
fn value_mappings(mappings: Vec<(String, String, String)>) -> Vec<ValueMapping> {
    if mappings.is_empty() {
        return Vec::new();
    }
    let options = mappings
        .into_iter()
        .zip(0_u32..)
        .map(|((value, text, color), index)| (value, ValueMappingResult { color, index, text }))
        .collect();
    vec![ValueMapping {
        kind: ValueMappingKind::Value,
        options,
    }]
}

/// A link opening `logql` in Explore over the dashboard's time range.
/// `logql` may use dashboard variables, e.g. `{sequencer="${sequencer}"}`.
#[must_use]
pub fn explore_logs_url(logql: &str) -> String {
    let pane = serde_json::json!({
        "logs": {
            "datasource": LOGS_DATASOURCE_UID,
            "queries": [{
                "refId": "A",
                "expr": logql,
                "datasource": Datasource::loki(),
            }],
            "range": { "from": "${__from}", "to": "${__to}" },
        }
    });
    format!(
        "/explore?schemaVersion=1&panes={}",
        query_value(&pane.to_string())
    )
}

/// `value` safe to put in a URL's query string: there `+` reads as a space, and
/// `&` and `#` end the value. Grafana's `$variables` stay as they are, for it
/// to fill in.
fn query_value(value: &str) -> String {
    value
        .chars()
        .map(|char| match char {
            '%' => "%25".to_owned(),
            '+' => "%2B".to_owned(),
            '&' => "%26".to_owned(),
            '#' => "%23".to_owned(),
            ' ' => "%20".to_owned(),
            other => other.to_string(),
        })
        .collect()
}

/// A per-minute rate target summing `metric`'s series, keeping `by` labels
/// apart, e.g. `&["sequencer"]` for one line per sequencer.
#[must_use]
pub fn sum_rate_per_min(metric: &Selector, by: &[&str], legend: &str) -> Target {
    let rate = format!("rate({metric}[{RATE_WINDOW}])");
    let sum = if by.is_empty() {
        format!("sum({rate})")
    } else {
        format!("sum by ({}) ({rate})", by.join(", "))
    };
    Target::new(format!("{sum} * 60")).legend(legend)
}

const fn default_unit() -> Unit {
    Unit::Short
}

fn ref_letter(index: usize) -> String {
    let offset = u8::try_from(index).unwrap_or(0);
    char::from(b'A'.saturating_add(offset)).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explore_links_keep_a_regex_plus_and_the_dashboard_variables() {
        let url = explore_logs_url(r#"{sequencer=~".+", level="$level"}"#);

        assert!(url.contains(r#"=~\".%2B\""#), "{url}");
        assert!(url.contains("$level"), "{url}");
        assert!(
            url.contains(r#""from":"${__from}","to":"${__to}""#),
            "{url}"
        );
        assert!(!url.contains('+'), "{url}");
    }
}
