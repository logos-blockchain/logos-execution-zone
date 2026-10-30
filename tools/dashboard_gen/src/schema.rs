//! The serializable Grafana dashboard schema — the internal data model the
//! public builders assemble into.
//!
//! Every type here is `Serialize`-only: the model is sized for what we emit.

use serde::Serialize;

use crate::{DATASOURCE_UID, FieldOverride, LOGS_DATASOURCE_UID, Target, unit::Unit};

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DatasourceKind {
    Prometheus,
    Loki,
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
}

#[derive(Clone, Copy, Serialize)]
pub enum PropertyId {
    #[serde(rename = "color")]
    Color,
    #[serde(rename = "custom.lineStyle")]
    LineStyle,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Calc {
    LastNotNull,
    Last,
    Max,
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
    pub unit: Unit,
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
    pub orientation: Orientation,
    pub reduce_options: ReduceOptions,
    pub show_unfilled: bool,
    pub value_mode: BarGaugeValueMode,
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
    pub include_all: bool,
    pub label: String,
    pub multi: bool,
    pub name: String,
    pub query: String,
    pub refresh: VariableRefresh,
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
    /// Upper bound on the points per series, and so a lower one on the step.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<PanelLink>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_data_points: Option<u32>,
    pub options: Options,
    pub targets: Vec<Target>,
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
