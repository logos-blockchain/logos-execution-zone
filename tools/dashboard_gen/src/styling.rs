//! Optional timeseries styling setters.
//!
//! These are real setters — each fills in a field of the panel's `custom` block.
//! Every one documents Grafana's default and **panics if handed that default**:
//! passing the default is always redundant (Grafana emits it anyway), and the
//! generator only serializes fields that differ from the default. So if a call
//! wouldn't change the rendered panel, it's a mistake worth catching loudly at
//! generation time rather than shipping a no-op.
//!
//! These affect timeseries panels only; on a stat panel the `custom` block is
//! not emitted, so the value is silently dropped.

use crate::{
    DEFAULT_FILL_OPACITY, Panel,
    schema::{AxisPlacement, GradientMode, LineInterpolation, ShowPoints, StackingMode},
};

#[expect(
    clippy::multiple_inherent_impl,
    reason = "styling setters intentionally live in their own file, so `Panel` has a second inherent impl here"
)]
impl Panel {
    /// Area fill under the line, as a percentage. Builder default:
    /// [`DEFAULT_FILL_OPACITY`].
    ///
    /// Panics if passed that default, or a value above 100.
    #[must_use]
    pub fn fill_opacity(mut self, opacity: u32) -> Self {
        assert!(
            opacity <= 100,
            "fill_opacity({opacity}) is not a percentage"
        );
        assert_ne!(
            opacity, DEFAULT_FILL_OPACITY,
            "fill_opacity({DEFAULT_FILL_OPACITY}) is redundant: it is the builder's default. Omit the call.",
        );
        self.fill_opacity = Some(opacity);
        self
    }

    /// Interpolation between points. Grafana default: `Linear`.
    ///
    /// Panics if passed `Linear` — that's the default and would be redundant.
    #[must_use]
    pub fn line_interpolation(mut self, value: LineInterpolation) -> Self {
        assert_ne!(
            value,
            LineInterpolation::Linear,
            "line_interpolation(Linear) is redundant: `linear` is Grafana's default. Omit the call.",
        );
        self.line_interpolation = Some(value);
        self
    }

    /// Whether/when to draw point markers. Grafana default: `Auto`.
    ///
    /// Panics if passed `Auto` — that's the default and would be redundant.
    #[must_use]
    pub fn show_points(mut self, value: ShowPoints) -> Self {
        assert_ne!(
            value,
            ShowPoints::Auto,
            "show_points(Auto) is redundant: `auto` is Grafana's default. Omit the call.",
        );
        self.show_points = Some(value);
        self
    }

    /// Area fill gradient. Grafana default: `None`.
    ///
    /// Panics if passed `None` — that's the default and would be redundant.
    #[must_use]
    pub fn gradient_mode(mut self, value: GradientMode) -> Self {
        assert_ne!(
            value,
            GradientMode::None,
            "gradient_mode(None) is redundant: `none` is Grafana's default. Omit the call.",
        );
        self.gradient_mode = Some(value);
        self
    }

    /// Series stacking. Grafana default: `None`.
    ///
    /// Panics if passed `None` — that's the default and would be redundant.
    #[must_use]
    pub fn stacking(mut self, mode: StackingMode) -> Self {
        assert_ne!(
            mode,
            StackingMode::None,
            "stacking(None) is redundant: `none` is Grafana's default. Omit the call.",
        );
        self.stacking = Some(mode);
        self
    }

    /// Y-axis placement. Grafana default: `Auto`.
    ///
    /// Panics if passed `Auto` — that's the default and would be redundant.
    #[must_use]
    pub fn axis_placement(mut self, value: AxisPlacement) -> Self {
        assert_ne!(
            value,
            AxisPlacement::Auto,
            "axis_placement(Auto) is redundant: `auto` is Grafana's default. Omit the call.",
        );
        self.axis_placement = Some(value);
        self
    }

    /// Y-axis label. Grafana default: `""` (no label).
    ///
    /// Panics if passed an empty string — that's the default and would be redundant.
    #[must_use]
    pub fn axis_label(mut self, label: impl Into<String>) -> Self {
        let label = label.into();
        assert_ne!(
            label, "",
            "axis_label(\"\") is redundant: no label is Grafana's default. Omit the call.",
        );
        self.axis_label = Some(label);
        self
    }
}
