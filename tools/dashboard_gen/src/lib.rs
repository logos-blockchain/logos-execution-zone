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
pub use schema::{
    AxisPlacement, Color, GradientMode, LineInterpolation, ShowPoints, StackingMode, Thresholds,
    Variable,
};
use schema::{
    Calc, Custom, Datasource, Defaults, DrawStyle, EmptyList, FieldConfig, Fill, GaugeOptions,
    GraphMode, GridPos, Legend, LegendDisplay, LineStyle, Matcher, MatcherKind, Options,
    OverrideProperty, PanelModel, PanelType, Placement, PropertyId, PropertyValue, ReduceOptions,
    SortOrder, Stacking, StatColorMode, StatOptions, Templating, TimeRange, TimeSeriesOptions,
    Tooltip, TooltipMode, VariableKind, VariableOption,
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

/// A single Prometheus query within a panel.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Target {
    datasource: Datasource,
    expr: String,
    #[serde(rename = "legendFormat")]
    legend: String,
    ref_id: String,
}

impl Target {
    pub fn new(expr: impl Into<String>) -> Self {
        Self {
            datasource: Datasource::prometheus(),
            expr: expr.into(),
            legend: String::new(),
            ref_id: ref_letter(0),
        }
    }

    #[must_use]
    pub fn legend(mut self, legend: impl Into<String>) -> Self {
        self.legend = legend.into();
        self
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
}

#[derive(Clone, Copy)]
enum Kind {
    Stat,
    TimeSeries,
    Gauge,
}

/// A dashboard panel builder. Grid position and panel id are assigned by
/// [`Dashboard::row`]; everything else is set here.
pub struct Panel {
    title: String,
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
    // Optional timeseries styling, set via the `styling` setters.
    fill_opacity: Option<u32>,
    line_interpolation: Option<LineInterpolation>,
    show_points: Option<ShowPoints>,
    gradient_mode: Option<GradientMode>,
    stacking: Option<StackingMode>,
    axis_placement: Option<AxisPlacement>,
    axis_label: Option<String>,
}

impl Panel {
    fn new(title: impl Into<String>, kind: Kind) -> Self {
        Self {
            title: title.into(),
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
            fill_opacity: None,
            line_interpolation: None,
            show_points: None,
            gradient_mode: None,
            stacking: None,
            axis_placement: None,
            axis_label: None,
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
                t.ref_id = ref_letter(i);
                t
            })
            .collect();

        let unit = self.unit.unwrap_or_else(default_unit);
        let (defaults, options, panel_type) = match self.kind {
            Kind::Stat => {
                let defaults = Defaults {
                    color: self.color,
                    custom: None,
                    unit,
                    decimals: self.decimals,
                    min: self.min,
                    max: self.max,
                    thresholds: self.thresholds,
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
                    unit,
                    decimals: self.decimals,
                    min: self.min,
                    max: self.max,
                    thresholds: self.thresholds,
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
                    color: None,
                    custom: Some(Custom {
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
                    }),
                    unit,
                    decimals: None,
                    min: self.min,
                    max: self.max,
                    thresholds: self.thresholds,
                };
                // Panels with several series read better as a sortable table with
                // a multi-series tooltip; single-series panels stay compact. A
                // `{{label}}` legend fans one target out into a series per label
                // value, so it counts as several too.
                let multi =
                    targets.len() > 1 || targets.iter().any(|target| target.legend.contains("{{"));
                let options = Options::TimeSeries(TimeSeriesOptions {
                    legend: Legend {
                        display_mode: if multi {
                            LegendDisplay::Table
                        } else {
                            LegendDisplay::List
                        },
                        placement: Placement::Bottom,
                        calcs: vec![Calc::Last, Calc::Max],
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
        };

        PanelModel {
            datasource: Datasource::prometheus(),
            field_config: FieldConfig {
                defaults,
                overrides: self.overrides,
            },
            grid_pos,
            id,
            options,
            targets,
            title: self.title,
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
    panels: Vec<PanelModel>,
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
        for panel in panels {
            let w = if panel.width == 0 {
                auto_width
            } else {
                panel.width
            };
            let grid_pos = GridPos {
                h: height,
                w,
                x,
                y: self.cursor_y,
            };
            let id = self.next_id;
            self.next_id = self.next_id.saturating_add(1);
            x = x.saturating_add(w);
            self.panels.push(panel.finalize(id, grid_pos));
        }
        self.cursor_y = self.cursor_y.saturating_add(height);
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

    Variable {
        current,
        include_all: false,
        label: "Percentile".to_owned(),
        // A quantile is a scalar argument to `histogram_quantile`, so exactly
        // one may be selected.
        multi: false,
        name: PERCENTILE_VAR.to_owned(),
        options,
        query,
        kind: VariableKind::Custom,
    }
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
pub fn selected_percentile(metric: &str, labels: &[&str], legend: &str) -> Target {
    // `le` carries the bucket boundary, so it must survive the aggregation.
    let grouping = std::iter::once("le")
        .chain(labels.iter().copied())
        .collect::<Vec<_>>()
        .join(", ");

    Target::new(format!(
        "histogram_quantile(${{{PERCENTILE_VAR}}}, sum by ({grouping}) (rate({metric}_bucket[{RATE_WINDOW}])))"
    ))
    .legend(legend)
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
pub fn avg(metric: &str) -> Target {
    Target::new(format!(
        "rate({metric}_sum[{RATE_WINDOW}]) / rate({metric}_count[{RATE_WINDOW}])"
    ))
    .legend("avg")
}

/// A per-minute rate target for a counter metric.
#[must_use]
pub fn rate_per_min(metric: &str, legend: &str) -> Target {
    //`rate` is per-second whatever the window, so `* 60` is per-minute regardless of the panel's
    //`rate` zoom.
    Target::new(format!("rate({metric}[{RATE_WINDOW}]) * 60")).legend(legend)
}

const fn default_unit() -> Unit {
    Unit::Short
}

fn ref_letter(index: usize) -> String {
    let offset = u8::try_from(index).unwrap_or(0);
    char::from(b'A'.saturating_add(offset)).to_string()
}
