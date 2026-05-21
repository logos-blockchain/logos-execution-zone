//! Small helper for best / mean / stdev over wall-time samples.
//!
//! We report both best-of-N (the figure that strips OS noise and matches what most
//! bench READMEs print) and mean +/- stdev (the figure the fee model wants, since
//! it cares about the steady-state cost not a single fastest sample).

use std::fmt;

use serde::Serialize;

#[derive(Debug, Serialize, Clone, Copy, Default)]
pub struct Stats {
    /// Number of samples in the aggregate (excluding warmup).
    pub n: usize,
    /// Lowest sample (ms). Strips OS jitter; matches the bench README "best of N" figure.
    pub best_ms: f64,
    /// Arithmetic mean of samples (ms).
    pub mean_ms: f64,
    /// Sample standard deviation of samples (ms), computed with Bessel's correction (n-1).
    /// 0.0 when n < 2.
    pub stdev_ms: f64,
}

impl Stats {
    pub fn from_samples(samples: &[f64]) -> Self {
        let n = samples.len();
        if n == 0 {
            return Self::default();
        }
        let best_ms = samples.iter().copied().fold(f64::INFINITY, f64::min);
        let sum: f64 = samples.iter().sum();
        let mean_ms = sum / n as f64;
        let stdev_ms = if n > 1 {
            let var: f64 = samples
                .iter()
                .map(|s| {
                    let d = s - mean_ms;
                    d * d
                })
                .sum::<f64>()
                / (n - 1) as f64;
            var.sqrt()
        } else {
            0.0
        };
        Self {
            n,
            best_ms,
            mean_ms,
            stdev_ms,
        }
    }
}

/// `best / mean ± stdev (n=N)` for table display.
impl fmt::Display for Stats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:.2} / {:.2} ± {:.2} (n={})",
            self.best_ms, self.mean_ms, self.stdev_ms, self.n,
        )
    }
}
