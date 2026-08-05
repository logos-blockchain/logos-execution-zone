//! Builds one of the Grafana dashboards and prints its JSON to stdout.

#![expect(
    clippy::print_stdout,
    reason = "CLI tool: emitting the dashboard JSON on stdout is the deliverable"
)]

use clap::{Parser, ValueEnum};
use dashboard_gen::Dashboard;
use json_pretty_compact::PrettyCompactFormatter;
use serde::Serialize as _;

mod dashboards;

#[derive(Debug, Parser)]
#[clap(version)]
struct Args {
    /// Which dashboard to build.
    dashboard: DashboardKind,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum DashboardKind {
    Sequencer,
}

impl DashboardKind {
    fn build(self) -> Dashboard {
        match self {
            Self::Sequencer => dashboards::sequencer::dashboard(),
        }
    }
}

fn main() {
    let Args { dashboard } = Args::parse();

    let formatter = PrettyCompactFormatter::new();
    let mut output = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut output, formatter);
    dashboard.build().serialize(&mut ser).unwrap();

    let json = String::from_utf8(output).unwrap();
    println!("{json}");
}
