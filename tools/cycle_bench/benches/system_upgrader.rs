//! Criterion bench for `system_upgrader`'s `Schedule` and `Apply`, end to end through
//! `transition_from_public_transaction`.
//!
//! - `Schedule`, swept over committee sizes: its cost is the approval checks.
//! - `Apply`, swept over the new code's size: its cost is `program_loader` walking the chain and
//!   recomputing the image ID, natively. Throughput is in bytes of user ELF, so the report reads as
//!   the loader's real rate per byte.
//!
//! Run with: `cargo bench -p cycle_bench --bench system_upgrader`.

use std::{hint::black_box, time::Duration};

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use cycle_bench::system_upgrader::{
    COMMITTEE_SIZES, FROM_HEIGHT, SCHEDULE_BLOCK, apply_tx, schedule_tx, scheduled, staged,
};

fn bench_schedule(c: &mut Criterion) {
    let mut group = c.benchmark_group("system_upgrader/schedule");
    group
        .sample_size(20)
        .measurement_time(Duration::from_secs(10));
    for committee_size in COMMITTEE_SIZES {
        let upgrade = staged(committee_size, &programs::ping_receiver());
        let tx = schedule_tx(&upgrade.segments, committee_size);
        group.bench_with_input(
            BenchmarkId::from_parameter(committee_size),
            &committee_size,
            |b, _| {
                b.iter_batched(
                    || upgrade.state.clone(),
                    |mut state| {
                        state
                            .transition_from_public_transaction(black_box(&tx), SCHEDULE_BLOCK, 0)
                            .expect("the upgrade schedules");
                    },
                    BatchSize::LargeInput,
                );
            },
        );
    }
    group.finish();
}

fn bench_apply(c: &mut Criterion) {
    let mut group = c.benchmark_group("system_upgrader/apply");
    group
        .sample_size(20)
        .measurement_time(Duration::from_secs(10));
    for (name, new_code) in [
        ("clock", programs::clock()),
        ("fee", programs::fee()),
        ("wrapped_token", programs::wrapped_token()),
        ("sequencer_stake", programs::sequencer_stake()),
    ] {
        let upgrade = scheduled(2, &new_code);
        let tx = apply_tx(&upgrade.segments);
        group.throughput(Throughput::Bytes(
            u64::try_from(upgrade.code_len).expect("code length fits in u64"),
        ));
        group.bench_with_input(
            BenchmarkId::new(name, upgrade.code_len),
            &upgrade.code_len,
            |b, _| {
                b.iter_batched(
                    || upgrade.state.clone(),
                    |mut state| {
                        state
                            .transition_from_public_transaction(black_box(&tx), FROM_HEIGHT, 0)
                            .expect("the upgrade applies");
                    },
                    BatchSize::LargeInput,
                );
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_schedule, bench_apply);
criterion_main!(benches);
