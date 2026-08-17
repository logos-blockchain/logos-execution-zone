use std::{
    collections::HashMap,
    fs::OpenOptions,
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, atomic::AtomicBool},
    time::{SystemTime, UNIX_EPOCH},
};

use cucumber::{
    StatsWriter as _, World as _, WriterExt as _, event::ScenarioFinished, writer,
    writer::Verbosity,
};
use integration_tests::cucumber::{
    default::{
        ARTEFACTS, CUCUMBER_REMOVE_ARTEFACTS_IF_SUCCESSFUL, MAX_CUCUMBER_CONCURRENT_SCENARIOS,
        create_scenario_output_dir, get_feature_path, get_retries,
    },
    world::CucumberWorld,
};
use logos_blockchain_testing_framework::{
    hash_str, is_truthy_env, reap_all_stale_port_blocks, release_reserved_port_block,
};
use tracing::{info, warn};
use wallet::SUPPRESS_VERBOSE_PRINTS;

pub const TARGET: &str = "cucumber_main";
type ScenarioAttempts = Arc<Mutex<HashMap<String, u8>>>;

#[tokio::main]
#[expect(clippy::print_stdout, reason = "Cucumber logs test code")]
async fn main() {
    logos_blockchain_testing_framework::env::set_default_env(SUPPRESS_VERBOSE_PRINTS, "true");
    integration_tests::cucumber::default::init_tracing();
    reap_all_stale_port_blocks();
    println!("args: {:?}", std::env::args());

    let scenario_attempts: ScenarioAttempts = Arc::new(Mutex::new(HashMap::new()));
    let teardown_failed = Arc::new(AtomicBool::new(false));

    let output_dir = create_scenario_output_dir();
    let junit_xml_file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(output_dir.join("cucumber-output-junit.xml"))
        .inspect_err(|err| warn!(target: TARGET, "Failed to open output file: {err}"))
        .expect("should create or open output file");
    let mut world = CucumberWorld::cucumber()
        // Re-outputs Failed steps for easier navigation.
        .repeat_failed()
        // .fail_fast() // Remove comment to enable fail-fast behavior for development
        .max_concurrent_scenarios(get_max_concurrent_scenarios())
        // Ensure that all the steps were covered.
        .fail_on_skipped()
        // Replaces Writer.
        .with_writer(
            writer::Summarize::new(writer::Basic::new(
                io::stdout(),
                // With `writer::Coloring::Auto`, cucumber treats the output as a TTY and using the
                // underlying termcolor/console behaviour that can rewrite/clear lines when
                // printing step statuses (✔ ...). That can visually clobber the
                // immediately adjacent tracing line, especially the one emitted
                // right as the step transitions from “running” to “passed”.
                writer::Coloring::Never,
                Verbosity::ShowWorldAndDocString,
            ))
                .tee::<CucumberWorld, _>(writer::JUnit::for_tee(junit_xml_file, 0))
                .normalized(),
        )
        // Sets a hook, executed on each Scenario before running all its Steps, including Background
        // ones.
        .before(move |feature, _rule, scenario, world| {
            Box::pin({
                let output_dir_clone = output_dir.clone();
                let scenario_attempts_clone = ScenarioAttempts::clone(&scenario_attempts);
                async move {
                    info!(target: TARGET,
                        "\nStarting - {}: {} ({}: {})\n",
                        scenario.keyword, scenario.name, feature.keyword, feature.name,
                    );
                    prepare_world_for_scenario(
                        world,
                        &output_dir_clone,
                        &scenario_attempts_clone,
                        &feature.name,
                        &scenario.name,
                    );
                }
            })
        });

    if let Some(retries) = get_retries()
        .inspect_err(|e| warn!(target: TARGET, "{e}"))
        .expect("should parse retries")
    {
        // Makes failed Scenarios being retried the specified number of times.
        world = world.retries(retries);
    }

    let teardown_failure_flag = Arc::clone(&teardown_failed);
    let failed = world
        .after(move |feature, _rule, scenario, scenario_finished, world| {
            let teardown_failure_flag = Arc::clone(&teardown_failure_flag);
            Box::pin(async move {
                // Runs after the scenario has completed; useful for capturing final state/logs.
                info!(target: TARGET,
                    "\nFinished - {}: {} ({}: {})\n",
                    scenario.keyword, scenario.name, feature.keyword, feature.name,
                );

                if let Some(world) = world {
                    let path = world.scenario_base_dir.join("debug_dump_file.log");
                    if let Some(parent) = path.parent() {
                        let _unused = std::fs::create_dir_all(parent);
                    }
                    let _initial_debug_write = std::fs::write(&path, world.full_debug_info_string());

                    let teardown_result = world.stop_runtime().await;
                    if let Err(error) = &teardown_result {
                        teardown_failure_flag.store(true, std::sync::atomic::Ordering::Relaxed);
                        warn!(target: TARGET, "Cucumber runtime teardown failed: {error}");
                    }

                    // Rewrite the dump after teardown so teardown state and
                    // any teardown error are retained for diagnostics. The
                    // first write above deliberately captures the live
                    // runtime state before handles are released.
                    let _final_debug_write = std::fs::write(&path, world.full_debug_info_string());

                    if teardown_result.is_ok()
                        && matches!(scenario_finished, ScenarioFinished::StepPassed)
                        && is_truthy_env(CUCUMBER_REMOVE_ARTEFACTS_IF_SUCCESSFUL)
                    {
                        info!(target: TARGET,
                            "Env var '{CUCUMBER_REMOVE_ARTEFACTS_IF_SUCCESSFUL}' set, removing all \
                            artefacts\n"
                        );
                        if let Err(e) = world.clear_scenario_artifacts() {
                            warn!(target: TARGET, "{e}");
                        }
                    }
                }
            })
        })
        // Runs Cucumber. Features sourced from a Parser are fed to a Runner, which
        // produces events handled by a Writer.
        .run(get_feature_path())
        .await;

    // Clean up manually reserved handshake port block files for this process
    release_reserved_port_block();

    if failed.execution_has_failed() || teardown_failed.load(std::sync::atomic::Ordering::Relaxed) {
        std::process::exit(1);
    }
}

// Get the maximum number of concurrent scenarios from env var, defaults to 1
fn get_max_concurrent_scenarios() -> usize {
    std::env::var(MAX_CUCUMBER_CONCURRENT_SCENARIOS)
        .ok()
        .and_then(|val| val.parse().ok())
        .unwrap_or(1)
}

fn prepare_world_for_scenario(
    world: &mut CucumberWorld,
    output_dir: &Path,
    scenario_attempts: &ScenarioAttempts,
    feature_name: &str,
    scenario_name: &str,
) {
    let scenario_dir =
        scenario_output_dir(output_dir, scenario_attempts, feature_name, scenario_name);

    if let Err(err) = std::fs::create_dir_all(&scenario_dir) {
        warn!(target: TARGET,
            "Failed to create scenario artifact directory '{}': {err}",
            scenario_dir.display()
        );
    }

    world.set_scenario_base_dir(&scenario_dir);
    world.apply_deployment_config_override_path();

    let started_at_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    let raw_context = format!("{}::{started_at_ns}", scenario_dir.display());
    world.set_test_context(hash_str(&raw_context));
}

fn scenario_output_dir(
    output_dir: &Path,
    scenario_attempts: &ScenarioAttempts,
    feature_name: &str,
    scenario_name: &str,
) -> PathBuf {
    let run_attempt = increment_attempts(scenario_attempts, feature_name, scenario_name);

    output_dir
        .join(ARTEFACTS)
        .join(feature_name)
        .join(scenario_name.trim().replace(' ', "_"))
        .join(run_attempt)
}

// Increment and return the attempt count for the given scenario. Counts
// are tracked per-scenario, and keyed by a combination of feature and
// scenario name.
#[expect(clippy::significant_drop_tightening, reason = "Compiler weirdness")]
fn increment_attempts(
    scenario_attempts: &ScenarioAttempts,
    feature: &str,
    scenario: &str,
) -> String {
    let mut guard = scenario_attempts
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let key = format!("{feature}::{scenario}");
    let entry = guard.entry(key).or_insert(0);
    *entry = entry.wrapping_add(1);
    format!("attempt_{}", *entry)
}
