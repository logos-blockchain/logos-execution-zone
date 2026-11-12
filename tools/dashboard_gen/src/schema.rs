//! The serializable Grafana dashboard schema — the internal data model the
//! public builders assemble into.
//!
//! Every type here is `Serialize`-only: the model is sized for what we emit.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::{
    DATASOURCE_UID, FieldOverride, LOGS_DATASOURCE_UID, TRACES_DATASOURCE_UID, Target, unit::Unit,
};

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DatasourceKind {
    Prometheus,
    Loki,
    Tempo,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Fill {
    Dash,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DrawStyle {
    Line,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum MatcherKind {
    ByName,
    ByRegexp,
}

#[derive(Clone, Copy, Serialize)]
pub enum PropertyId {
    #[serde(rename = "color")]
    Color,
    #[serde(rename = "custom.lineStyle")]
    LineStyle,
    #[serde(rename = "links")]
    Links,
    /// A table column left out of view, its values still there for links.
    #[serde(rename = "custom.hidden")]
    Hidden,
    /// A table column's width, in pixels.
    #[serde(rename = "custom.width")]
    Width,
    #[serde(rename = "unit")]
    Unit,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Calc {
    LastNotNull,
    Last,
    Max,
    Sum,
    Count,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum StatColorMode {
    Value,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GraphMode {
    Area,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LegendDisplay {
    Table,
    List,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Placement {
    Bottom,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TooltipMode {
    Single,
    Multi,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SortOrder {
    Desc,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PanelType {
    Stat,
    Timeseries,
    Gauge,
    #[serde(rename = "bargauge")]
    BarGauge,
    Logs,
    StateTimeline,
    StatusHistory,
    #[serde(rename = "nodeGraph")]
    NodeGraph,
    Table,
    Traces,
    Row,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ThresholdMode {
    Absolute,
    /// Steps expressed as a percentage of the min–max range. The builder never
    /// emits this; it exists so Grafana exports using it still parse.
    Percentage,
}

/// One threshold step: the color values at or above `value` take. The base step
/// carries `value: null` — Grafana's "everything below the first threshold".
#[derive(Clone, Serialize)]
pub struct ThresholdStep {
    pub color: String,
    pub value: Option<f64>,
}

/// A threshold ladder, driving gauge/stat coloring.
#[derive(Clone, Serialize)]
pub struct Thresholds {
    pub mode: ThresholdMode,
    pub steps: Vec<ThresholdStep>,
}

impl Thresholds {
    /// Start a ladder with the color used below every threshold.
    pub fn base(color: impl Into<String>) -> Self {
        Self {
            mode: ThresholdMode::Absolute,
            steps: vec![ThresholdStep {
                color: color.into(),
                value: None,
            }],
        }
    }

    /// Add a step: values at or above `value` render in `color`.
    #[must_use]
    pub fn step(mut self, value: f64, color: impl Into<String>) -> Self {
        self.steps.push(ThresholdStep {
            color: color.into(),
            value: Some(value),
        });
        self
    }
}

// Optional timeseries styling vocabularies. Each derives `PartialEq` so the
// public setters can panic when handed the Grafana default (see `styling`).

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum LineInterpolation {
    Linear,
    Smooth,
    StepBefore,
    StepAfter,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ShowPoints {
    Auto,
    Never,
    Always,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GradientMode {
    None,
    Opacity,
    Hue,
    Scheme,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum StackingMode {
    None,
    Normal,
    Percent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AxisPlacement {
    Auto,
    Left,
    Right,
    Hidden,
}

#[derive(Serialize)]
pub struct Stacking {
    pub mode: StackingMode,
    pub group: String,
}

/// The panel-type-specific `custom` block of a field config.
#[derive(Serialize)]
#[serde(untagged)]
pub enum CustomConfig {
    TimeSeries(Custom),
    Timeline(TimelineCustom),
}

/// `custom` for the timeline panels: state timeline and status history.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineCustom {
    pub line_width: u32,
    pub fill_opacity: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Custom {
    pub draw_style: DrawStyle,
    pub line_width: u32,
    pub fill_opacity: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span_nulls: Option<bool>,
    // Optional styling — omitted (left at Grafana's default) unless a setter
    // fills it in. See `styling`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_interpolation: Option<LineInterpolation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub show_points: Option<ShowPoints>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gradient_mode: Option<GradientMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stacking: Option<Stacking>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub axis_placement: Option<AxisPlacement>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub axis_label: Option<String>,
}

#[derive(Clone, Serialize)]
pub struct Datasource {
    #[serde(rename = "type")]
    pub kind: DatasourceKind,
    pub uid: String,
}

impl Datasource {
    pub fn prometheus() -> Self {
        Self {
            kind: DatasourceKind::Prometheus,
            uid: DATASOURCE_UID.to_owned(),
        }
    }

    pub fn loki() -> Self {
        Self {
            kind: DatasourceKind::Loki,
            uid: LOGS_DATASOURCE_UID.to_owned(),
        }
    }

    pub fn tempo() -> Self {
        Self {
            kind: DatasourceKind::Tempo,
            uid: TRACES_DATASOURCE_UID.to_owned(),
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
#[serde(tag = "mode")]
pub enum Color {
    Fixed {
        #[serde(rename = "fixedColor")]
        fixed_color: String,
    },
    PaletteClassic,
    /// Light to dark blue as the value grows.
    ContinuousBlues,
}

impl Color {
    pub fn fixed(color: impl Into<String>) -> Self {
        Self::Fixed {
            fixed_color: color.into(),
        }
    }

    #[must_use]
    pub const fn palette_classic() -> Self {
        Self::PaletteClassic
    }

    #[must_use]
    pub const fn continuous_blues() -> Self {
        Self::ContinuousBlues
    }
}

#[derive(Serialize)]
pub struct LineStyle {
    pub dash: [u32; 2],
    pub fill: Fill,
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum PropertyValue {
    Color(Color),
    LineStyle(LineStyle),
    Links(Vec<DataLink>),
    Flag(bool),
    Pixels(u32),
    Unit(Unit),
}

#[derive(Serialize)]
pub struct OverrideProperty {
    pub id: PropertyId,
    pub value: PropertyValue,
}

#[derive(Serialize)]
pub struct Matcher {
    pub id: MatcherKind,
    pub options: String,
}

/// Display text and color for one exact value.
#[derive(Serialize)]
pub struct ValueMappingResult {
    pub color: String,
    pub index: u32,
    pub text: String,
}

/// A `value` mapping: exact values (as strings) to display text and color.
#[derive(Serialize)]
pub struct ValueMapping {
    #[serde(rename = "type")]
    pub kind: ValueMappingKind,
    pub options: std::collections::BTreeMap<String, ValueMappingResult>,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ValueMappingKind {
    Value,
}

/// A link on every value of the panel, e.g. to another dashboard.
#[derive(Serialize)]
pub struct DataLink {
    pub title: String,
    pub url: String,
}

#[derive(Serialize)]
pub struct Defaults {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<Color>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom: Option<CustomConfig>,
    /// None leaves each field the unit its datasource gives it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<Unit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decimals: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thresholds: Option<Thresholds>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mappings: Vec<ValueMapping>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<DataLink>,
}

impl Defaults {
    /// None set: each field keeps what its datasource gives it.
    pub const fn empty() -> Self {
        Self {
            color: None,
            custom: None,
            unit: None,
            decimals: None,
            min: None,
            max: None,
            thresholds: None,
            mappings: Vec::new(),
            links: Vec::new(),
        }
    }
}

#[derive(Serialize)]
pub struct FieldConfig {
    pub defaults: Defaults,
    pub overrides: Vec<FieldOverride>,
}

#[derive(Serialize)]
pub struct ReduceOptions {
    pub calcs: Vec<Calc>,
    // Empty string means "all fields"; genuinely free-form, not a vocabulary.
    pub fields: String,
    pub values: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatOptions {
    pub color_mode: StatColorMode,
    pub graph_mode: GraphMode,
    pub reduce_options: ReduceOptions,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Legend {
    pub display_mode: LegendDisplay,
    pub placement: Placement,
    pub calcs: Vec<Calc>,
    #[serde(
        default,
        rename = "showLegend",
        skip_serializing_if = "Option::is_none"
    )]
    pub shown: Option<bool>,
}

#[derive(Serialize)]
pub struct Tooltip {
    pub mode: TooltipMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sort: Option<SortOrder>,
}

#[derive(Serialize)]
pub struct TimeSeriesOptions {
    pub legend: Legend,
    pub tooltip: Tooltip,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GaugeOptions {
    pub reduce_options: ReduceOptions,
    pub show_threshold_labels: bool,
    pub show_threshold_markers: bool,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Orientation {
    Horizontal,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BarGaugeDisplay {
    Basic,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BarGaugeValueMode {
    /// Values in text color rather than their bar's.
    Text,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BarGaugeOptions {
    pub display_mode: BarGaugeDisplay,
    pub max_viz_height: u32,
    pub min_viz_height: u32,
    pub min_viz_width: u32,
    pub name_placement: NamePlacement,
    pub orientation: Orientation,
    pub reduce_options: ReduceOptions,
    pub show_unfilled: bool,
    pub sizing: BarGaugeSizing,
    pub value_mode: BarGaugeValueMode,
}

/// How a bar gauge sizes its bars.
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BarGaugeSizing {
    /// Within `minVizHeight..=maxVizHeight`, scrolling the panel once the
    /// bars no longer fit.
    Manual,
}

/// Where a bar gauge puts each bar's name.
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NamePlacement {
    /// Above the bar, even when it is the only one: Grafana's `auto` hides a
    /// lone bar's name.
    Top,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ShowValue {
    Auto,
    Never,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AlignValue {
    Left,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StateTimelineOptions {
    pub align_value: AlignValue,
    pub legend: Legend,
    /// Adjacent equal values render as one bar.
    pub merge_values: bool,
    pub row_height: f64,
    pub show_value: ShowValue,
    pub tooltip: Tooltip,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusHistoryOptions {
    pub col_width: f64,
    pub legend: Legend,
    pub row_height: f64,
    pub show_value: ShowValue,
    pub tooltip: Tooltip,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeGraphOptions {
    pub edges: NodeGraphStats,
    pub nodes: NodeGraphStats,
    pub zoom_mode: ZoomMode,
}

/// How a node graph shows its nodes' or edges' `mainstat` field.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeGraphStats {
    pub main_stat_unit: Unit,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TableOptions {
    pub cell_height: CellHeight,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub footer: Option<TableFooter>,
    pub show_header: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sort_by: Vec<TableSort>,
}

/// A row under a table's others, here counting them.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TableFooter {
    pub count_rows: bool,
    /// Empty for every field.
    pub fields: String,
    pub reducer: Vec<Calc>,
    pub show: bool,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CellHeight {
    Sm,
}

/// The column a table is sorted by, by its name as shown.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TableSort {
    pub desc: bool,
    pub display_name: String,
}

/// The options of a panel with none to set.
#[expect(
    clippy::empty_structs_with_brackets,
    reason = "Serialized as `{}`, where a unit struct is `null`"
)]
#[derive(Serialize)]
pub struct NoOptions {}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ZoomMode {
    /// The wheel scrolls the dashboard, and zooms with Ctrl or Cmd held.
    Cooperative,
}

/// A step reshaping a panel's query results before it draws them.
#[derive(Serialize)]
#[serde(tag = "id", content = "options", rename_all = "camelCase")]
pub enum Transformation {
    CalculateField(CalculateField),
    Organize(Organize),
    RenameByRegex(RenameByRegex),
}

/// Renames the series whose names match `regex` to `rename_pattern`, which
/// may use its capture groups, e.g. `$1`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RenameByRegex {
    pub regex: String,
    pub rename_pattern: String,
}

/// Leaves out, orders and renames a table's columns, each by its name as
/// shown, which may differ from the field's own.
#[expect(clippy::struct_field_names, reason = "Grafana's names for them")]
#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Organize {
    pub exclude_by_name: BTreeMap<String, bool>,
    pub index_by_name: BTreeMap<String, u32>,
    pub rename_by_name: BTreeMap<String, String>,
}

/// Adds the field `alias` to every row.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CalculateField {
    pub alias: String,
    pub mode: CalculateMode,
    pub reduce: RowReduce,
    pub replace_fields: bool,
    /// Whether frames are joined by time first, rather than each taken alone.
    pub time_series: bool,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum CalculateMode {
    /// The row's number fields, reduced to one.
    ReduceRow,
}

#[derive(Serialize)]
pub struct RowReduce {
    pub reducer: Calc,
}

/// How a query's result is laid out.
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TargetFormat {
    /// One row per series, its labels in columns.
    Table,
}

/// The language of a [`Target`]'s `query`.
#[derive(Clone, Copy, Serialize)]
pub enum QueryType {
    #[serde(rename = "traceql")]
    TraceQl,
}

/// How a trace search's result is laid out.
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TableType {
    /// One row per matching span, its trace's id in `traceIdHidden`.
    Spans,
}

#[derive(Clone, Copy, Serialize)]
pub enum LogsSortOrder {
    Descending,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogsOptions {
    /// Each line's labels and parsed fields, on click.
    pub enable_log_details: bool,
    pub show_time: bool,
    pub sort_order: LogsSortOrder,
    pub wrap_log_message: bool,
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum Options {
    Stat(StatOptions),
    TimeSeries(TimeSeriesOptions),
    Gauge(GaugeOptions),
    BarGauge(BarGaugeOptions),
    StateTimeline(StateTimelineOptions),
    StatusHistory(StatusHistoryOptions),
    Logs(LogsOptions),
    NodeGraph(NodeGraphOptions),
    Table(TableOptions),
    None(NoOptions),
}

/// One choice in a [`CustomVariable`] dropdown: `text` is displayed, `value` is
/// what `$name` interpolates to in a query.
#[derive(Clone, Serialize)]
pub struct VariableOption {
    pub selected: bool,
    pub text: String,
    pub value: String,
}

/// A dashboard-level dropdown, rendered in the top bar.
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Variable {
    Custom(CustomVariable),
    Query(QueryVariable),
    Textbox(TextboxVariable),
}

/// A text field, which links can fill in too.
#[derive(Serialize)]
pub struct TextboxVariable {
    pub label: String,
    pub name: String,
    /// The text it starts with.
    pub query: String,
}

/// A fixed list of choices, spelled out in the dashboard itself.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomVariable {
    pub current: VariableOption,
    pub include_all: bool,
    pub label: String,
    pub multi: bool,
    pub name: String,
    pub options: Vec<VariableOption>,
    /// Grafana's own encoding of `options`, as `text : value` pairs.
    pub query: String,
}

/// Choices fetched from the datasource. Grafana picks the first one on load.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryVariable {
    pub datasource: Datasource,
    /// What the variable editor displays; Grafana keeps it equal to `query`.
    pub definition: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hide: Option<VariableHide>,
    pub include_all: bool,
    pub label: String,
    pub multi: bool,
    pub name: String,
    pub query: String,
    pub refresh: VariableRefresh,
    /// JavaScript regex, slashes included, whose first capture group becomes
    /// each choice's text and value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
    pub sort: VariableSort,
}

/// When a [`QueryVariable`] re-fetches its choices.
#[derive(Clone, Copy)]
pub enum VariableRefresh {
    /// Also picks up sources that appeared since the dashboard was opened.
    OnTimeRangeChange,
}

impl Serialize for VariableRefresh {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let id = match self {
            Self::OnTimeRangeChange => 2,
        };
        serializer.serialize_u8(id)
    }
}

/// What of a [`QueryVariable`] the top bar leaves out.
#[derive(Clone, Copy)]
pub enum VariableHide {
    /// The whole dropdown: the dashboard derives the value, no one picks it.
    Variable,
}

impl Serialize for VariableHide {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let id = match self {
            Self::Variable => 2,
        };
        serializer.serialize_u8(id)
    }
}

/// Order of a [`QueryVariable`]'s choices.
#[derive(Clone, Copy)]
pub enum VariableSort {
    /// Ascending, with digit runs compared as numbers (`seq_2` before `seq_10`).
    NaturalAsc,
}

impl Serialize for VariableSort {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let id = match self {
            Self::NaturalAsc => 7,
        };
        serializer.serialize_u8(id)
    }
}

#[derive(Serialize, Default)]
pub struct Templating {
    pub list: Vec<Variable>,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DashboardLinkKind {
    /// Every dashboard carrying one of `tags`.
    Dashboards,
}

/// A link in the dashboard's top bar.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardLink {
    pub as_dropdown: bool,
    pub include_vars: bool,
    pub keep_time: bool,
    pub tags: Vec<String>,
    pub title: String,
    #[serde(rename = "type")]
    pub kind: DashboardLinkKind,
}

#[derive(Clone, Copy, Serialize)]
pub struct GridPos {
    pub h: u32,
    pub w: u32,
    pub x: u32,
    pub y: u32,
}

/// A link in a panel's header.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PanelLink {
    pub target_blank: bool,
    pub title: String,
    pub url: String,
}

/// A fully positioned panel, ready to serialize.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PanelModel {
    pub datasource: Datasource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub field_config: FieldConfig,
    pub grid_pos: GridPos,
    pub id: u32,
    /// Lower bound on the query step, and so on `$__interval`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<PanelLink>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Upper bound on the points per series, and so a lower one on the step.
    pub max_data_points: Option<u32>,
    pub options: Options,
    pub targets: Vec<Target>,
    pub title: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transformations: Vec<Transformation>,
    #[serde(rename = "type")]
    pub panel_type: PanelType,
}

/// An entry of a dashboard's panel list: a panel, or a row heading.
#[derive(Serialize)]
#[serde(untagged)]
pub enum DashboardPanel {
    Panel(Box<PanelModel>),
    Row(RowModel),
}

/// A row heading. An open row holds the panels after it, up to the next
/// heading; a folded one holds its own, in `panels`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RowModel {
    pub collapsed: bool,
    pub grid_pos: GridPos,
    pub id: u32,
    pub panels: Vec<PanelModel>,
    pub title: String,
    #[serde(rename = "type")]
    pub panel_type: PanelType,
}

#[expect(
    clippy::trailing_empty_array,
    reason = "Grafana expects `list: []` for the blocks we don't populate"
)]
#[derive(Serialize, Default)]
pub struct EmptyList {
    pub list: [u8; 0],
}

#[derive(Serialize)]
pub struct TimeRange {
    // Free-form Grafana time expressions, not a closed vocabulary.
    pub from: String,
    pub to: String,
}
