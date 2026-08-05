//! Prover side of union aggregation: folds `n` succinct PPE receipts into one root
//! receipt with `n - 1` fixed-size recursion proofs (no guest execution).

use risc0_zkvm::{ProverOpts, SuccinctReceipt, Unknown, get_prover_server};

use super::mmr::{MerkleMountainAccumulator, Peak};
use crate::error::LeeError;

/// Result of a union aggregation run.
pub struct UnionAggregation {
    /// The root receipt, claim pruned to its digest: for `n >= 2` a union receipt, for
    /// `n == 1` the single input receipt itself. Verify it against the batch's public
    /// data with [`super::verify_union_aggregation`].
    pub root: SuccinctReceipt<Unknown>,
    /// Number of union recursion proofs performed (`n - 1`).
    pub unions_performed: usize,
}

/// Receipt-bearing peak: merging two peaks runs one union recursion proof.
///
/// Mirror of risc0-zkvm 3.0.5 `UnionPeak`.
struct ReceiptPeak {
    item: SuccinctReceipt<Unknown>,
    height: u32,
}

impl Peak for ReceiptPeak {
    type Item = SuccinctReceipt<Unknown>;

    fn new(item: Self::Item) -> Self {
        Self::new_with_height(item, 0)
    }

    fn new_with_height(item: Self::Item, height: u32) -> Self {
        Self { item, height }
    }

    fn height(&self) -> u32 {
        self.height
    }

    fn item(self) -> Self::Item {
        self.item
    }

    fn merge_item(a: &mut Self::Item, b: Self::Item) -> Result<(), LeeError> {
        *a = union_receipts(a, &b)?;
        Ok(())
    }
}

/// One union recursion proof over two succinct receipts.
///
/// `risc0_zkvm::recursion::prove::union` itself is not publicly re-exported in 3.0.5,
/// so this goes through the public [`get_prover_server`]/`ProverServer::union` surface,
/// whose implementation calls the same function (and additionally verifies the
/// resulting receipt's integrity). Constructing the prover server is a trivial
/// allocation, so one per call keeps this usable from multiple threads
/// (`get_prover_server` returns an `Rc`, which cannot be shared across them).
fn union_receipts(
    a: &SuccinctReceipt<Unknown>,
    b: &SuccinctReceipt<Unknown>,
) -> Result<SuccinctReceipt<Unknown>, LeeError> {
    let prover = get_prover_server(&ProverOpts::succinct())
        .map_err(|e| LeeError::UnionAggregation(format!("prover server unavailable: {e}")))?;
    Ok(prover
        .union(a, b)
        .map_err(|e| LeeError::UnionAggregation(format!("union proving failed: {e}")))?
        .into_unknown())
}

/// Errors out when the dev-mode environment flag is set.
///
/// The union path never fakes proofs (the recursion prover has no dev mode), but a
/// benchmark or caller running with `RISC0_DEV_MODE=1` would be comparing against
/// dev-mode-faked *inputs*, and any surrounding measurements would be meaningless —
/// so refuse loudly instead.
fn ensure_not_dev_mode(dev_mode: bool) -> Result<(), LeeError> {
    crate::ensure!(
        !dev_mode,
        LeeError::UnionAggregation(
            "refusing to run union aggregation with RISC0_DEV_MODE set".into()
        )
    );
    Ok(())
}

/// Reads the same environment flag risc0 treats as enabling dev mode.
fn dev_mode_env_flag() -> bool {
    std::env::var("RISC0_DEV_MODE")
        .map(|value| {
            let value = value.to_lowercase();
            value == "1" || value == "true" || value == "yes"
        })
        .unwrap_or(false)
}

/// Aggregates succinct receipts into one root receipt, sequentially.
///
/// This is the reference implementation: a literal Merkle-mountain-accumulator insert
/// loop, structurally identical to risc0's own `MerkleMountainAccumulator<UnionPeak>`.
/// Convert `SuccinctReceipt<ReceiptClaim>` inputs with
/// [`SuccinctReceipt::into_unknown`] first.
pub fn aggregate_union(
    leaves: Vec<SuccinctReceipt<Unknown>>,
) -> Result<UnionAggregation, LeeError> {
    ensure_not_dev_mode(dev_mode_env_flag())?;
    crate::ensure!(
        !leaves.is_empty(),
        LeeError::UnionAggregation("cannot aggregate an empty batch".into())
    );

    let unions_performed = leaves.len().saturating_sub(1);
    let mut mmr = MerkleMountainAccumulator::<ReceiptPeak>::new();
    for leaf in leaves {
        mmr.insert(leaf)?;
    }

    Ok(UnionAggregation {
        root: mmr.root()?,
        unions_performed,
    })
}

/// Aggregates succinct receipts into one root receipt, running up to `max_parallel`
/// union proofs concurrently.
///
/// Produces a root receipt whose claim is byte-identical to [`aggregate_union`]'s: the
/// leaves are split into consecutive chunks sized by the powers of two of `n`'s binary
/// decomposition (most significant first), each chunk is reduced level-synchronously by
/// adjacent pairs (the parallel part — unions within a level are independent), and the
/// chunk roots are folded left to right (a chain of at most `log2(n)` sequential
/// unions). This is exactly the accumulator's shape, and the union program orders each
/// node's children by digest, so the pairing shape is all that matters.
///
/// `max_parallel <= 1` degenerates to the sequential implementation. Each union proof
/// runs the recursion prover on its own thread; on a single GPU, concurrent proofs
/// contend for VRAM — measure before raising `max_parallel` there.
pub fn aggregate_union_parallel(
    leaves: Vec<SuccinctReceipt<Unknown>>,
    max_parallel: usize,
) -> Result<UnionAggregation, LeeError> {
    if max_parallel <= 1 {
        return aggregate_union(leaves);
    }
    ensure_not_dev_mode(dev_mode_env_flag())?;
    crate::ensure!(
        !leaves.is_empty(),
        LeeError::UnionAggregation("cannot aggregate an empty batch".into())
    );

    let unions_performed = leaves.len().saturating_sub(1);

    // Consecutive chunks sized by the powers of two of n, most significant first.
    let mut chunk_roots = Vec::new();
    let mut rest = leaves;
    while !rest.is_empty() {
        let size = 1_usize << rest.len().ilog2();
        let chunk: Vec<SuccinctReceipt<Unknown>> = rest.drain(..size).collect();
        chunk_roots.push(reduce_chunk(chunk, max_parallel)?);
    }

    // Chunk heights strictly decrease left to right, so this fold is inherently
    // sequential — it mirrors the accumulator's front-to-back root fold.
    // TODO: chunks are currently reduced one after another; overlapping the smaller
    // chunks' unions with the tail levels of the biggest chunk would shave a little
    // wall-clock for non-power-of-two n.
    let mut roots = chunk_roots.into_iter();
    let mut root = roots
        .next()
        .expect("non-empty input yields at least one chunk");
    for next in roots {
        root = union_receipts(&root, &next)?;
    }

    Ok(UnionAggregation {
        root,
        unions_performed,
    })
}

/// Reduces one power-of-two-sized chunk to its root, level by level, proving the
/// unions of each level in waves of at most `max_parallel` concurrent threads.
fn reduce_chunk(
    mut level: Vec<SuccinctReceipt<Unknown>>,
    max_parallel: usize,
) -> Result<SuccinctReceipt<Unknown>, LeeError> {
    debug_assert!(
        level.len().is_power_of_two(),
        "reduce_chunk expects a power-of-two chunk; an odd level would silently drop a receipt"
    );
    while level.len() > 1 {
        let mut pairs = Vec::with_capacity(level.len() >> 1_u32);
        let mut items = level.into_iter();
        while let (Some(a), Some(b)) = (items.next(), items.next()) {
            pairs.push((a, b));
        }
        level = union_pairs(pairs, max_parallel)?;
    }
    level
        .pop()
        .ok_or_else(|| LeeError::UnionAggregation("cannot reduce an empty chunk".into()))
}

/// Proves the union of each pair, at most `max_parallel` concurrently, preserving
/// order.
fn union_pairs(
    pairs: Vec<(SuccinctReceipt<Unknown>, SuccinctReceipt<Unknown>)>,
    max_parallel: usize,
) -> Result<Vec<SuccinctReceipt<Unknown>>, LeeError> {
    let mut results = Vec::with_capacity(pairs.len());
    let mut pending = pairs.into_iter();
    loop {
        let wave: Vec<(SuccinctReceipt<Unknown>, SuccinctReceipt<Unknown>)> =
            pending.by_ref().take(max_parallel).collect();
        if wave.is_empty() {
            break;
        }
        let wave_results: Vec<Result<SuccinctReceipt<Unknown>, LeeError>> = std::thread::scope(
            |scope| {
                #[expect(
                    clippy::needless_collect,
                    reason = "every worker must be spawned before the first join, or the wave would run serially"
                )]
                let handles: Vec<_> = wave
                    .into_iter()
                    .map(|(a, b)| scope.spawn(move || union_receipts(&a, &b)))
                    .collect();
                handles
                    .into_iter()
                    .map(|handle| {
                        handle.join().unwrap_or_else(|_panic_payload| {
                            Err(LeeError::UnionAggregation("union worker panicked".into()))
                        })
                    })
                    .collect()
            },
        );
        for result in wave_results {
            results.push(result?);
        }
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use lee_core::PrivacyPreservingCircuitOutput;
    use risc0_zkvm::{InnerReceipt, ReceiptClaim, sha::Digestible as _};
    use test_program_methods::PpeFixture;

    use super::*;
    use crate::{
        PRIVACY_PRESERVING_CIRCUIT_ID,
        union_aggregation::{expected_root_claim_digest, verify_union_aggregation},
    };

    /// Block id the checked-in fixtures were generated for.
    const FIXTURE_BLOCK_ID: u64 = 1;
    /// Timestamp the checked-in fixtures were generated for.
    const FIXTURE_TIMESTAMP: u64 = 1_700_000_000;

    /// Loads fixtures and decodes outputs; empty when the fixture file is absent.
    fn load_fixture_outputs() -> (Vec<PpeFixture>, Vec<PrivacyPreservingCircuitOutput>) {
        let path = std::env::var("PPE_FIXTURES").unwrap_or_else(|_| "ppe_fixtures.bin".to_owned());
        let fixtures = PpeFixture::load_bundle(&path);
        let outputs = fixtures
            .iter()
            .map(|fixture| {
                let words: &[u32] = bytemuck::cast_slice(&fixture.output_bytes);
                risc0_zkvm::serde::from_slice(words).expect("fixture output_bytes invalid")
            })
            .collect();
        (fixtures, outputs)
    }

    /// Extracts each fixture's succinct receipt, claim pruned.
    fn fixture_leaves(fixtures: &[PpeFixture]) -> Vec<SuccinctReceipt<Unknown>> {
        fixtures
            .iter()
            .map(|fixture| {
                let inner: InnerReceipt = borsh::from_slice(&fixture.proof_bytes)
                    .expect("fixture proof_bytes is not a valid InnerReceipt");
                let InnerReceipt::Succinct(receipt) = inner else {
                    panic!("fixture receipt is not succinct")
                };
                receipt.into_unknown()
            })
            .collect()
    }

    /// True when the dev-mode env flag forbids running the real recursion prover.
    fn skip_under_dev_mode(test: &str) -> bool {
        if dev_mode_env_flag() {
            #[expect(
                clippy::print_stderr,
                reason = "skip notice, mirroring the fixture-absent skip convention"
            )]
            {
                eprintln!("[union_aggregation tests] {test}: RISC0_DEV_MODE is set - skipping");
            }
            return true;
        }
        false
    }

    #[test]
    fn dev_mode_guard_rejects() {
        assert!(ensure_not_dev_mode(true).is_err());
        assert!(ensure_not_dev_mode(false).is_ok());
    }

    /// The native leaf reconstruction must match each fixture receipt's actual claim:
    /// `ReceiptClaim::ok(PPE image id, journal bytes)` digest == the succinct receipt's
    /// claim digest. This pins the whole binding chain's first link without proving
    /// anything.
    #[test]
    fn fixture_leaf_claims_match_native_reconstruction() {
        let (fixtures, outputs) = load_fixture_outputs();
        if fixtures.is_empty() {
            return; // fixtures absent - load_bundle printed a skip notice
        }

        for (index, (fixture, output)) in fixtures.iter().zip(&outputs).enumerate() {
            let inner: InnerReceipt = borsh::from_slice(&fixture.proof_bytes)
                .expect("fixture proof_bytes is not a valid InnerReceipt");
            let InnerReceipt::Succinct(receipt) = inner else {
                panic!("fixture {index} receipt is not succinct");
            };
            let expected =
                ReceiptClaim::ok(PRIVACY_PRESERVING_CIRCUIT_ID, output.to_bytes()).digest();
            assert_eq!(
                receipt.claim.digest(),
                expected,
                "fixture {index} ({}): native ReceiptClaim reconstruction diverges from \
                 the receipt's actual claim",
                fixture.label
            );
        }
    }

    /// Sequential union aggregation produces exactly the natively recomputed root
    /// digest, and the full public-data verification passes, for a spread of batch
    /// sizes (1 = no union, 2 = single union, 3 = uneven fold, 5 = two chunks).
    ///
    /// Runs the real recursion prover — this is the expensive byte-compatibility test.
    #[test]
    fn union_root_matches_native_digest_and_verifies() {
        if skip_under_dev_mode("union_root_matches_native_digest_and_verifies") {
            return;
        }
        let (fixtures, outputs) = load_fixture_outputs();
        if fixtures.is_empty() {
            return;
        }

        for n in [1_usize, 2, 3, 5] {
            if fixtures.len() < n {
                continue;
            }
            let aggregation =
                aggregate_union(fixture_leaves(&fixtures[..n])).expect("aggregation succeeds");
            assert_eq!(aggregation.unions_performed, n - 1);

            let expected = expected_root_claim_digest(&outputs[..n]).expect("digest fold succeeds");
            assert_eq!(
                aggregation.root.claim.digest(),
                expected,
                "root claim digest mismatch at n={n}"
            );

            verify_union_aggregation(
                &outputs[..n],
                FIXTURE_BLOCK_ID,
                FIXTURE_TIMESTAMP,
                &aggregation.root,
            )
            .expect("public-data verification succeeds");

            if n == 2 {
                // Sibling transposition: the union program orders each node's two
                // children by digest, so swapping the two elements of a pair yields
                // the SAME root digest — verification still passes. This is by
                // design (batch semantics are order-independent) and pinned here so
                // nobody later relies on intra-pair order being bound.
                // (`PrivacyPreservingCircuitOutput` has no `Clone`; re-decode instead.)
                let (_refixtures, mut redecoded) = load_fixture_outputs();
                redecoded.truncate(2);
                redecoded.swap(0, 1);
                verify_union_aggregation(
                    &redecoded,
                    FIXTURE_BLOCK_ID,
                    FIXTURE_TIMESTAMP,
                    &aggregation.root,
                )
                .expect("sibling transposition within a pair keeps the same root");

                let mut tampered = aggregation.root.clone();
                tampered.seal[0] ^= 1;
                assert!(
                    verify_union_aggregation(
                        &outputs[..2],
                        FIXTURE_BLOCK_ID,
                        FIXTURE_TIMESTAMP,
                        &tampered,
                    )
                    .is_err(),
                    "verification must reject a tampered seal"
                );

                let root_bytes = borsh::to_vec(&aggregation.root).expect("root serializes");
                let restored: SuccinctReceipt<Unknown> =
                    borsh::from_slice(&root_bytes).expect("root deserializes");
                verify_union_aggregation(
                    &outputs[..2],
                    FIXTURE_BLOCK_ID,
                    FIXTURE_TIMESTAMP,
                    &restored,
                )
                .expect("verification passes after a serialization round-trip");
            }

            if n == 3 {
                // Reordering ACROSS the tree's pairing (leaf 0 <-> leaf 2 moves an
                // output between tree levels) changes the root digest and must be
                // rejected — unlike the intra-pair swap above.
                let (_refixtures, mut redecoded) = load_fixture_outputs();
                redecoded.truncate(3);
                redecoded.swap(0, 2);
                assert!(
                    verify_union_aggregation(
                        &redecoded,
                        FIXTURE_BLOCK_ID,
                        FIXTURE_TIMESTAMP,
                        &aggregation.root,
                    )
                    .is_err(),
                    "verification must reject a batch reordered across the pairing"
                );

                // Substituting an output that was never proven into the batch must
                // also be rejected.
                let (_subfixtures, mut substituted) = load_fixture_outputs();
                if substituted.len() >= 4 {
                    substituted.swap(2, 3);
                    substituted.truncate(3);
                    assert!(
                        verify_union_aggregation(
                            &substituted,
                            FIXTURE_BLOCK_ID,
                            FIXTURE_TIMESTAMP,
                            &aggregation.root,
                        )
                        .is_err(),
                        "verification must reject a batch with a substituted output"
                    );
                }
            }
        }
    }

    /// Benchmark: union-aggregate `PPE_FIXTURES_COUNT` pre-generated PPE proofs.
    ///
    /// Mirrors `aggregate_ppe_proofs_from_fixtures` (the guest-based benchmark this
    /// approach is compared against). Control via env vars:
    /// - `PPE_FIXTURES`: fixture file path (default: `ppe_fixtures.bin`; skips when
    ///   absent).
    /// - `PPE_FIXTURES_COUNT`: number of proofs to aggregate (default: all).
    /// - `UNION_PARALLEL`: max concurrent union proofs; `0`/`1` = sequential
    ///   (default), `k > 1` = parallel with `k` workers.
    ///
    /// `PPE_SEGMENT_LIMIT_PO2` is deliberately not read: recursion proofs are fixed
    /// size (no guest execution, no segments).
    ///
    /// Output line (captured by `bench_ppe_union.sh` / `bench_ppe_union_cuda.sh`):
    /// `[lee::analytics] ppe_union n=… mode=… proving_ms=… verify_ms=… unions=…
    /// proof_size_bytes=… public_bytes=… total_material_bytes=…`
    /// where `proof_size_bytes` is the Borsh-encoded root receipt,
    /// `public_bytes` the summed journals (per-transaction public data), and
    /// `total_material_bytes` their sum — everything a verifier needs.
    ///
    /// Comparability with `aggregate_ppe_proofs_from_fixtures` (the guest benchmark):
    /// its `proof_size_bytes` is `borsh(InnerReceipt)` with an unpruned claim (a few
    /// hundred bytes more framing than the pruned `SuccinctReceipt<Unknown>` here) and
    /// its journal (≈ `public_bytes` + vector framing) also travels in its receipt.
    /// Union proving is in-process, so run BOTH benchmarks from `--release` builds
    /// when comparing (the old scripts build debug by default — pass `--release`
    /// manually or compare against a release run).
    #[test]
    fn bench_union_ppe_proofs_from_fixtures() {
        if skip_under_dev_mode("bench_union_ppe_proofs_from_fixtures") {
            return; // benchmark numbers under dev mode would be meaningless
        }

        let (mut fixtures, mut outputs) = load_fixture_outputs();
        if fixtures.is_empty() {
            return; // fixtures absent - load_bundle printed a skip notice
        }
        if let Ok(count_str) = std::env::var("PPE_FIXTURES_COUNT") {
            let count: usize = count_str
                .parse()
                .expect("PPE_FIXTURES_COUNT must be a number");
            fixtures.truncate(count);
            outputs.truncate(count);
        }

        let max_parallel: usize = std::env::var("UNION_PARALLEL").ok().map_or(1, |value| {
            value.parse().expect("UNION_PARALLEL must be a number")
        });
        let mode = if max_parallel > 1 {
            format!("par{max_parallel}")
        } else {
            "seq".to_owned()
        };

        let leaves = fixture_leaves(&fixtures);
        let n = leaves.len();

        let proving_started = std::time::Instant::now();
        let aggregation = if max_parallel > 1 {
            aggregate_union_parallel(leaves, max_parallel)
        } else {
            aggregate_union(leaves)
        }
        .expect("union aggregation should succeed");
        let proving_ms = proving_started.elapsed().as_millis();

        let verify_started = std::time::Instant::now();
        verify_union_aggregation(
            &outputs,
            FIXTURE_BLOCK_ID,
            FIXTURE_TIMESTAMP,
            &aggregation.root,
        )
        .expect("aggregated batch must verify from public data");
        let verify_ms = verify_started.elapsed().as_millis();

        let proof_size = borsh::to_vec(&aggregation.root)
            .expect("root receipt serializes")
            .len();
        let public_bytes: usize = fixtures
            .iter()
            .map(|fixture| fixture.output_bytes.len())
            .sum();
        let total_material_bytes = public_bytes.saturating_add(proof_size);

        #[expect(
            clippy::print_stderr,
            reason = "benchmark result line consumed by tooling"
        )]
        {
            eprintln!(
                "[lee::analytics] ppe_union n={n} mode={mode} proving_ms={proving_ms} \
                 verify_ms={verify_ms} unions={} proof_size_bytes={proof_size} \
                 public_bytes={public_bytes} total_material_bytes={total_material_bytes}",
                aggregation.unions_performed,
            );
        }
    }

    /// The parallel schedule must produce the identical root claim digest (the shape
    /// argument: chunk decomposition + digest-ordered children == accumulator fold).
    #[test]
    fn parallel_union_matches_native_digest() {
        if skip_under_dev_mode("parallel_union_matches_native_digest") {
            return;
        }
        let (fixtures, outputs) = load_fixture_outputs();
        if fixtures.len() < 5 {
            return;
        }

        let aggregation = aggregate_union_parallel(fixture_leaves(&fixtures[..5]), 4)
            .expect("parallel aggregation succeeds");
        let expected = expected_root_claim_digest(&outputs[..5]).expect("digest fold succeeds");
        assert_eq!(
            aggregation.root.claim.digest(),
            expected,
            "parallel root claim digest diverges from the sequential/native shape"
        );
    }
}
