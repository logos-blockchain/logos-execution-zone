//! Panel value units.
//!
//! Grafana identifies a field's unit by a short id string (`"s"`, `"bytes"`,
//! `"reqps"`, …). We model the handful we actually use as named variants and
//! fall back to [`Unit::custom`] for anything else, so the value always
//! serializes to the exact id Grafana expects.

use serde::{Serialize, Serializer};

/// A panel value unit. Serializes to Grafana's unit id string.
///
/// Only the most common units are named; [`Unit::custom`] carries any other
/// Grafana unit id verbatim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unit {
    /// Plain number, SI-abbreviated (`short`). Grafana's default.
    Short,
    /// Percentage on a 0–100 scale (`percent`).
    Percent,
    /// Percentage on a 0.0–1.0 scale (`percentunit`).
    PercentUnit,
    /// Seconds (`s`).
    Seconds,
    /// Milliseconds (`ms`).
    Milliseconds,
    /// Nanoseconds (`ns`).
    Nanoseconds,
    /// Bytes, IEC/binary (`bytes`).
    Bytes,
    /// Bytes per second, SI (`Bps`).
    BytesPerSec,
    /// Requests per second (`reqps`).
    RequestsPerSec,
    /// Operations per second (`ops`).
    OpsPerSec,
    /// Any other Grafana unit id, kept verbatim.
    Custom(String),
}

impl Unit {
    /// Wrap an arbitrary Grafana unit id (e.g. `"dtdurationms"`, `"celsius"`).
    #[must_use]
    pub fn custom(id: impl Into<String>) -> Self {
        Self::Custom(id.into())
    }

    /// The Grafana unit id this value serializes to.
    fn as_id(&self) -> &str {
        match self {
            Self::Short => "short",
            Self::Percent => "percent",
            Self::PercentUnit => "percentunit",
            Self::Seconds => "s",
            Self::Milliseconds => "ms",
            Self::Nanoseconds => "ns",
            Self::Bytes => "bytes",
            Self::BytesPerSec => "Bps",
            Self::RequestsPerSec => "reqps",
            Self::OpsPerSec => "ops",
            Self::Custom(id) => id,
        }
    }
}

impl Serialize for Unit {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_id())
    }
}
