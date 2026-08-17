#![expect(
    clippy::float_arithmetic,
    reason = "One should expect floating point arithmetic in statistic calculations"
)]
#![expect(
    clippy::cast_precision_loss,
    reason = "Operated numbers is not big enough to have precision loss"
)]

use std::{collections::HashMap, path::Path, sync::Arc};

use anyhow::{Context as _, Result};
use common::{HashType, config::BasicAuth, transaction::LeeTransaction};
use itertools::Itertools as _;
use lee_core::BlockId;
use sequencer_service_rpc::{RpcClient as _, SequencerClient, SequencerClientBuilder};
use serde::{Deserialize, Serialize};
use tokio::{sync::RwLock, task::JoinSet};
use url::Url;

use crate::{
    ExecutionFailureKind,
    config::{MultiSequencerClientConfig, SequencerConnectionData},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Statistics {
    pub latency_avg: f32,
    pub latency_var: f32,
    pub sample_size: usize,
    pub latest_block_id: BlockId,
    pub errors: u64,
}

#[derive(Debug, Clone)]
pub enum StatisticsUpdate {
    Success {
        latency: f32,
        new_latest_block_id: BlockId,
    },
    Failure,
}

impl Statistics {
    pub fn apply_updates(&mut self, updates: &[StatisticsUpdate]) {
        let CumulativeUpdates {
            failure_count,
            latest_block_id,
            cumulative_latency,
            cumulative_latency_squares,
            additional_sample_size,
        } = CumulativeUpdates::from_metric_updates(updates);

        self.errors = self.errors.saturating_add(failure_count);
        if let Some(latest_block_id) = latest_block_id {
            self.latest_block_id = latest_block_id;
        }

        #[expect(clippy::as_conversions, reason = "int to float conversion is safe")]
        let orig_size_f = self.sample_size as f32;
        #[expect(clippy::as_conversions, reason = "int to float conversion is safe")]
        let mod_size_f = additional_sample_size as f32;

        let latency_avg_old = self.latency_avg;
        let latency_avg_new =
            cumulative_avg(latency_avg_old, cumulative_latency, orig_size_f, mod_size_f);

        let latency_var_new = cumulative_var(
            latency_avg_old,
            latency_avg_new,
            self.latency_var,
            cumulative_latency,
            cumulative_latency_squares,
            orig_size_f,
            mod_size_f,
        );

        self.latency_avg = latency_avg_new;
        self.latency_var = latency_var_new;
        self.sample_size = self.sample_size.saturating_add(additional_sample_size);
    }
}

#[derive(Clone)]
pub struct MultiSequencerClient {
    /// Ordered list of leaders, from best to worst.
    leader_list: Vec<(SequencerClient, Url)>,
    config: MultiSequencerClientConfig,
    /// Wrapping statistic updates in Arc<RwLock> to not break interfaces too much.
    ///  
    /// It is assumed, that wallet methods can be accesed via immutable reference.
    statistic_updates: Arc<RwLock<HashMap<Url, Vec<StatisticsUpdate>>>>,
}

impl MultiSequencerClient {
    async fn setup(
        conn_data: &[SequencerConnectionData],
        statistics: &mut HashMap<Url, Statistics>,
        multi_sequencer_client_config: &MultiSequencerClientConfig,
    ) -> Result<Vec<(SequencerClient, Url)>> {
        if !conn_data
            .iter()
            .map(|conn| &conn.sequencer_addr)
            .all_unique()
        {
            anyhow::bail!("All addresses must be unique");
        }

        let mut actualization_list = vec![];
        let mut calibration_list = vec![];
        let mut client_list = vec![];

        for SequencerConnectionData {
            sequencer_addr,
            basic_auth,
        } in conn_data
        {
            let sequencer_client = make_subclient(sequencer_addr, basic_auth)?;

            if statistics.contains_key(sequencer_addr) {
                actualization_list.push((sequencer_addr.clone(), sequencer_client.clone()));
            } else {
                calibration_list.push((sequencer_addr.clone(), sequencer_client.clone()));
            }

            client_list.push((sequencer_addr.clone(), sequencer_client));
        }

        // This actually starts in one thread, but each exact future produces more tasks.
        let (actualization_res, callibration_res) = tokio::join!(
            multi_actualize_clients(actualization_list),
            multi_calibrate_clients(
                calibration_list,
                multi_sequencer_client_config.calibration_limit
            )
        );

        for (addr, statistic_opt) in callibration_res {
            if let Some(statistic) = statistic_opt {
                statistics.insert(addr, statistic);
            }
        }

        for (addr, statistic_update_opt) in actualization_res {
            if let Some(statistic_mut) = statistics.get_mut(&addr)
                && let Some(statistic_update) = statistic_update_opt
            {
                statistic_mut.apply_updates(&[statistic_update]);
            }
        }

        let leader_list = choose_leaders(
            client_list,
            statistics,
            multi_sequencer_client_config.distribution_limit,
        )
        .ok_or_else(|| anyhow::anyhow!("Failed to find leader"))?;

        if leader_list.is_empty() {
            anyhow::bail!(
                "Leader search algorithm failure: Sorted out all clients during leader search"
            );
        }

        log::info!(
            "Chosen leaders is {:?}",
            leader_list.iter().map(|(_, addr)| addr).collect::<Vec<_>>()
        );

        Ok(leader_list)
    }

    pub async fn new(
        conn_data: &[SequencerConnectionData],
        statistics: &mut HashMap<Url, Statistics>,
        multi_sequencer_client_config: MultiSequencerClientConfig,
    ) -> Result<Self> {
        let leader_list =
            Self::setup(conn_data, statistics, &multi_sequencer_client_config).await?;

        Ok(Self {
            leader_list,
            config: multi_sequencer_client_config,
            statistic_updates: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Re-choose leader, `statistic_updates` must be empty.
    pub async fn rotate(
        &mut self,
        conn_data: &[SequencerConnectionData],
        statistics: &mut HashMap<Url, Statistics>,
        multi_sequencer_client_config: &MultiSequencerClientConfig,
    ) -> Result<()> {
        let leader_list = Self::setup(conn_data, statistics, multi_sequencer_client_config).await?;

        log::info!(
            "Chosen leaders is {:?}",
            leader_list.iter().map(|(_, addr)| addr).collect::<Vec<_>>()
        );

        self.leader_list = leader_list;

        Ok(())
    }

    #[must_use]
    pub fn leaders(&self) -> &[(SequencerClient, Url)] {
        self.leader_list.as_ref()
    }

    #[must_use]
    pub fn helm(&self) -> &(SequencerClient, Url) {
        self.leader_list
            .first()
            .expect("At least one leader must be set")
    }

    #[must_use]
    pub const fn config(&self) -> &MultiSequencerClientConfig {
        &self.config
    }

    /// Helperfunction for the `metered_get`.
    async fn metered_get_helper<R, E, I: AsyncFn(&SequencerClient) -> Result<R, E>>(
        &self,
        call: &I,
        leader: &SequencerClient,
        leader_url: &Url,
        statistic_map: &mut HashMap<Url, Vec<StatisticsUpdate>>,
    ) -> Result<R, E> {
        let (resp, statistics_update) =
            tokio::join!(call(leader), actualize_client(leader.clone()));

        log::debug!("Metered call for {leader_url:?}, statistic updates is {statistics_update:?}",);

        statistic_map
            .entry(leader_url.clone())
            .or_default()
            .push(statistics_update);

        resp
    }

    /// Metered call for main leader(helm), to get data, necessary for send call.
    ///
    /// If current leader errors, we ask next one in list up to a `self.config.distribution_limit`.
    pub async fn metered_get<R, E, I: AsyncFn(&SequencerClient) -> Result<R, E>>(
        &self,
        call: I,
    ) -> Result<R, E> {
        // Collecting all statistics into one map to lock updates only once
        let mut statistic_map: HashMap<Url, Vec<StatisticsUpdate>> = HashMap::new();

        // We need helm response to avoid constructing guard Result<R, E>, which we can not do with
        // generics.
        let (helm, helm_url) = self.helm();

        let mut resp = self
            .metered_get_helper(&call, helm, helm_url, &mut statistic_map)
            .await;

        // Not the cleanest approach, but I am not sure how to have it both clean and async.
        if resp.is_err() {
            for (leader, leader_url) in self.leaders().iter().skip(1) {
                resp = self
                    .metered_get_helper(&call, leader, leader_url, &mut statistic_map)
                    .await;

                if resp.is_ok() {
                    break;
                }
            }
        }

        {
            let mut statistic_updates_guard = self.statistic_updates.write().await;

            #[expect(
                clippy::iter_over_hash_type,
                reason = "Ordering of map updates is not important"
            )]
            for (url, updates) in statistic_map {
                statistic_updates_guard
                    .entry(url)
                    .or_insert_with(Vec::new)
                    .extend(updates);
            }
        }

        resp
    }

    /// Metered `send_transaction` for `distribution_limit` amount of leaders.
    ///
    /// Less abstract than it could be, clean way to implement it in a more general way is
    /// "return-type notation".
    ///
    /// `ToDo`: Return to it, when "return-type notation" is stable.
    pub async fn metered_send_transaction(
        &self,
        tx: LeeTransaction,
    ) -> Vec<Result<HashType, ExecutionFailureKind>> {
        // Collecting all statistics into one map to lock updates only once
        let mut statistic_map: HashMap<Url, Vec<StatisticsUpdate>> = HashMap::new();

        let mut results = vec![];
        let mut join_set = JoinSet::new();

        for (leader, leader_url) in self.leaders() {
            let curr_leader = leader.clone();
            let curr_tx = tx.clone();
            let curr_url = leader_url.clone();

            join_set.spawn(async move {
                (
                    tokio::join!(
                        curr_leader.send_transaction(curr_tx),
                        actualize_client(curr_leader.clone())
                    ),
                    curr_url,
                )
            });
        }

        while let Some(resp) = join_set.join_next().await {
            let res = resp
                .inspect_err(|j_err| log::warn!("Task failed with join error: {j_err:?}"))
                .map_err(Into::into)
                .and_then(|((resp, statistics_update), leader_url)| {
                    log::debug!(
                        "Metered call for {leader_url:?}, statistic updates is {statistics_update:?}",
                    );

                    statistic_map
                        .entry(leader_url)
                        .or_default()
                        .push(statistics_update);

                    resp.map_err(Into::into)
                });

            results.push(res);
        }

        {
            let mut statistic_updates_guard = self.statistic_updates.write().await;

            #[expect(
                clippy::iter_over_hash_type,
                reason = "Ordering of map updates is not important"
            )]
            for (url, updates) in statistic_map {
                statistic_updates_guard
                    .entry(url)
                    .or_insert_with(Vec::new)
                    .extend(updates);
            }
        }

        results
    }

    /// Update statistics of a leader, clear statistic updates log.
    pub async fn update_statistics(&self, statistics: &mut HashMap<Url, Statistics>) -> Result<()> {
        let mut statistic_updates = self.statistic_updates.write().await;

        #[expect(clippy::iter_over_hash_type, reason = "Ordering is unnecesary here")]
        for (addr, statistic_updates_vec) in statistic_updates.iter() {
            let leader_statistic = statistics
                .get_mut(addr)
                .ok_or_else(|| anyhow::anyhow!("Leader statistic must be present after setup"))?;
            leader_statistic.apply_updates(statistic_updates_vec.as_slice());
        }

        statistic_updates.clear();

        Ok(())
    }
}

struct CumulativeUpdates {
    pub failure_count: u64,
    pub latest_block_id: Option<BlockId>,
    /// Necessary for cumulative average calculation.
    pub cumulative_latency: f32,
    /// Necessary for cumulative variance calculation.
    pub cumulative_latency_squares: f32,
    pub additional_sample_size: usize,
}

impl CumulativeUpdates {
    fn from_metric_updates(metric_updates: &[StatisticsUpdate]) -> Self {
        let (failure_count, latest_block_id, cumulative_latency, cumulative_latency_squares) =
            metric_updates
                .iter()
                .fold((0_u64, None, 0_f32, 0_f32), |mut acc, x| {
                    match x {
                        StatisticsUpdate::Success {
                            latency,
                            new_latest_block_id,
                        } => {
                            match acc.1 {
                                Some(val_old) => {
                                    acc.1 = Some(std::cmp::max(val_old, *new_latest_block_id));
                                }
                                None => {
                                    acc.1 = Some(*new_latest_block_id);
                                }
                            }
                            acc.2 += latency;
                            acc.3 = latency.mul_add(*latency, acc.3);
                        }
                        StatisticsUpdate::Failure => {
                            acc.0 = acc.0.saturating_add(1);
                        }
                    }
                    acc
                });

        Self {
            failure_count,
            latest_block_id,
            cumulative_latency,
            cumulative_latency_squares,
            additional_sample_size: metric_updates.len().saturating_sub(
                usize::try_from(failure_count).expect("Sample size should fit usize"),
            ),
        }
    }
}

pub fn extract_statistics_from_path(
    path: &Path,
) -> Result<HashMap<Url, Statistics>, anyhow::Error> {
    match std::fs::File::open(path) {
        Ok(file) => {
            let reader = std::io::BufReader::new(file);
            Ok(serde_json::from_reader(reader)?)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            println!("Statistics not found, choosing empty");
            Ok(HashMap::new())
        }
        Err(err) => Err(err).context("IO error"),
    }
}

/// Measuring `get_last_block_id` as it should be the fastest request on sequencer.
async fn measure_request_duration(client: &SequencerClient) -> (u128, Option<BlockId>) {
    let now = tokio::time::Instant::now();
    let block_id = client.get_last_block_id().await.ok();
    (
        tokio::time::Instant::now().duration_since(now).as_millis(),
        block_id,
    )
}

pub fn make_subclient(
    sequencer_addr: &Url,
    basic_auth: &Option<BasicAuth>,
) -> Result<SequencerClient> {
    let mut builder = SequencerClientBuilder::default();
    if let Some(basic_auth) = &basic_auth {
        builder = builder.set_headers(
            std::iter::once((
                "Authorization".parse().expect("Header name is valid"),
                format!("Basic {basic_auth}")
                    .parse()
                    .context("Invalid basic auth format")?,
            ))
            .collect(),
        );
    }
    builder
        .build(sequencer_addr)
        .context("Failed to create sequencer client")
}

/// Calibrate statistics for one client. Takes `client` by value deliberately, cloning
/// `SequencerClient` is cheap.
pub async fn calibrate_client(
    client: SequencerClient,
    calibration_limit: usize,
) -> Option<Statistics> {
    let mut latencies = vec![];
    let mut latest_block_id = 0;
    let mut errors: u64 = 0;

    // ToDo: Add some DDoS adaptation
    for _ in 0..calibration_limit {
        let (latency, block_id) = measure_request_duration(&client).await;

        let Some(block_id) = block_id else {
            errors = errors.saturating_add(1);
            continue;
        };

        latest_block_id = block_id;
        latencies.push(latency);
    }

    // There is no point in guard numbers, exclude client if it fails all requests.
    if latencies.is_empty() {
        return None;
    }

    // Precision loss is fine there
    let sample_size = latencies.len();
    #[expect(clippy::as_conversions, reason = "int to float conversion is safe")]
    let latency_avg = (latencies.iter().sum::<u128>() as f32) / (sample_size as f32);
    #[expect(clippy::as_conversions, reason = "int to float conversion is safe")]
    let latency_var = latencies.iter().fold(0_f32, |acc, x| {
        ((*x as f32) - latency_avg).mul_add((*x as f32) - latency_avg, acc)
    }) / (sample_size as f32);

    Some(Statistics {
        latency_avg,
        latency_var,
        sample_size,
        latest_block_id,
        errors,
    })
}

/// Actualize statistics for one client. Takes `client` by value deliberately, cloning
/// `SequencerClient` is cheap.
async fn actualize_client(client: SequencerClient) -> StatisticsUpdate {
    let (latency, block_id) = measure_request_duration(&client).await;

    #[expect(clippy::as_conversions, reason = "int to float conversion is safe")]
    let latency = latency as f32;

    block_id.map_or(StatisticsUpdate::Failure, |new_latest_block_id| {
        StatisticsUpdate::Success {
            latency,
            new_latest_block_id,
        }
    })
}

// Next 2 functions can be done in uniform way right now, but it will be incredibly cursed.
// ToDo: Return to it when "return-type notation" is stable

async fn multi_actualize_clients(
    clients: Vec<(Url, SequencerClient)>,
) -> Vec<(Url, Option<StatisticsUpdate>)> {
    let mut handle_map = HashMap::new();

    for (url, client) in clients {
        // `client` here must have 'static lifetime, so we can not use reference
        let actualization_task = tokio::task::spawn(actualize_client(client));
        handle_map.insert(url, actualization_task);
    }

    let mut statistic_updates = vec![];

    // We anyhow need results of each one
    #[expect(
        clippy::iter_over_hash_type,
        reason = "Ordering of map updates is not important"
    )]
    for (url, task) in handle_map {
        let task_opt = task.await.ok();
        statistic_updates.push((url, task_opt));
    }

    statistic_updates
}

async fn multi_calibrate_clients(
    clients: Vec<(Url, SequencerClient)>,
    calibration_limit: usize,
) -> Vec<(Url, Option<Statistics>)> {
    let mut handle_map = HashMap::new();

    for (url, client) in clients {
        // `client` here must have 'static lifetime, so we can not use reference
        let calibration_task = tokio::task::spawn(calibrate_client(client, calibration_limit));
        handle_map.insert(url, calibration_task);
    }

    let mut statistics = vec![];

    // We anyhow need results of each one
    #[expect(
        clippy::iter_over_hash_type,
        reason = "Ordering of map updates is not important"
    )]
    for (url, task) in handle_map {
        let task_opt = task
            .await
            .ok()
            .inspect(|val| {
                if val.is_none() {
                    log::warn!(
                        "Client {url:?} failed all {calibration_limit} calibration attempts, it may be unhealthy.
                    \n Consider bumping calibration_limit or remove this client altogether"
                    );
                }
            })
            .flatten();
        statistics.push((url, task_opt));
    }

    statistics
}

/// Choosing leaders up to a `distribution_limit`.
///
/// Assumes that all clients have their statistics in `statistics`.
#[must_use]
fn choose_leaders(
    client_vec: Vec<(Url, SequencerClient)>,
    statistics: &HashMap<Url, Statistics>,
    distribution_limit: usize,
) -> Option<Vec<(SequencerClient, Url)>> {
    // Sort out all unmetered clients
    let client_vec: Vec<_> = client_vec
        .into_iter()
        .filter(|item| statistics.contains_key(&item.0))
        .collect();

    if client_vec.is_empty() {
        return None;
    }

    // Considering the nature of our requests, the latest_block_id is the dominant characteristic
    let max_block_id_addr = client_vec
        .iter()
        .fold(client_vec.first().unwrap(), |acc, x| {
            let old_latest_block_id = statistics.get(&acc.0).unwrap().latest_block_id;
            let new_latest_block_id = statistics.get(&x.0).unwrap().latest_block_id;
            if new_latest_block_id > old_latest_block_id {
                x
            } else {
                acc
            }
        });

    let max_block_id = statistics
        .get(&max_block_id_addr.0)
        .unwrap()
        .latest_block_id;

    // Sort out all clients running late
    let mut res_vec: Vec<_> = client_vec
        .into_iter()
        .filter(|x| {
            let latest_block_id = statistics.get(&x.0).unwrap().latest_block_id;

            latest_block_id == max_block_id
        })
        .collect();

    // Get the clients with lesser or equal to average error ratio
    #[expect(clippy::as_conversions, reason = "int to float conversion is safe")]
    let avg_err_ratio = res_vec.iter().fold(0_f32, |acc, x| {
        acc + error_ratio(
            statistics.get(&x.0).unwrap().errors,
            statistics.get(&x.0).unwrap().sample_size,
        )
    }) / (res_vec.len() as f32);

    res_vec.sort_by(|a, b| {
        let err_ratio_a = error_ratio(
            statistics.get(&a.0).unwrap().errors,
            statistics.get(&a.0).unwrap().sample_size,
        );
        let err_ratio_b = error_ratio(
            statistics.get(&b.0).unwrap().errors,
            statistics.get(&b.0).unwrap().sample_size,
        );

        err_ratio_a
            .partial_cmp(&err_ratio_b)
            .expect("Ratios must be a valid numbers")
    });

    res_vec.truncate(
        res_vec
            .iter()
            .position(|item| {
                error_ratio(
                    statistics.get(&item.0).unwrap().errors,
                    statistics.get(&item.0).unwrap().sample_size,
                ) > avg_err_ratio
            })
            .unwrap_or(res_vec.len()),
    );

    // Choose clients with least latency and variance
    res_vec.sort_by(|a, b| {
        let left = statistics.get(&a.0).unwrap();
        let (left_lat, left_var) = (left.latency_avg, left.latency_var);
        let right = statistics.get(&b.0).unwrap();
        let (right_lat, right_var) = (right.latency_avg, right.latency_var);

        let right_std = right_var.sqrt();
        let left_std = left_var.sqrt();

        // Client is better if its average + std is lesser:
        // [-right_std < right_lat < +left_std < +right_std]
        (left_lat + left_std).total_cmp(&(right_lat + right_std))
    });

    Some(
        res_vec
            .into_iter()
            .map(|(a, b)| (b, a))
            .take(distribution_limit)
            .collect(),
    )
}

/// Helperfunction to calculate cumulative average.
///
/// Cumulative average calculation is the following problem:
///
/// We want to calculate avarage of a sample of size `N + N_1`
/// where average for `N` is known.
///
/// To do so we need:
/// - old average value
/// - sum_{`i=1}^{N_1}{n_i`}
/// - `N`
/// - `N_1`
fn cumulative_avg(
    latency_avg_old: f32,
    cumulative_latency: f32,
    orig_size_f: f32,
    mod_size_f: f32,
) -> f32 {
    latency_avg_old.mul_add(orig_size_f, cumulative_latency) / (orig_size_f + mod_size_f)
}

/// Helperfunction to calculate cumulative variance.
///
/// Cumulative variance calculation is the following problem:
///
/// We want to calculate variance of a sample of size `N + N_1`
/// where average for `N` is known.
///
/// To do so we need:
/// - old average value
/// - new average value
/// - old variance
/// - sum_{`i=1}^{N_1}{n_i`}
/// - sum_{`i=1}^{N_1}{n_i^2`}
/// - `N`
/// - `N_1`
fn cumulative_var(
    latency_avg_old: f32,
    latency_avg_new: f32,
    latency_var: f32,
    cumulative_latency: f32,
    cumulative_latency_squares: f32,
    orig_size_f: f32,
    mod_size_f: f32,
) -> f32 {
    // The formula was atrocious before.
    // `mul_add` function have less precision loss with drawback of being absolutely unreadable
    ((2_f32 * cumulative_latency).mul_add(
        -latency_avg_new,
        mod_size_f.mul_add(
            latency_avg_new * latency_avg_new,
            latency_var.mul_add(
                orig_size_f,
                (latency_avg_new - latency_avg_old)
                    * (latency_avg_new - latency_avg_old)
                    * orig_size_f,
            ),
        ),
    ) + cumulative_latency_squares)
        / (orig_size_f + mod_size_f)
}

fn error_ratio(errors: u64, size: usize) -> f32 {
    #[expect(clippy::as_conversions, reason = "int to float conversion is safe")]
    let errors_f = errors as f32;
    #[expect(clippy::as_conversions, reason = "int to float conversion is safe")]
    let size_f = size as f32;

    errors_f / (errors_f + size_f)
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use sequencer_service_rpc::{SequencerClient, SequencerClientBuilder};
    use url::Url;

    use crate::multi_client::{
        CumulativeUpdates, Statistics, StatisticsUpdate, choose_leaders, cumulative_avg,
        cumulative_var,
    };

    fn update_statistics(
        statistics: &mut HashMap<Url, Statistics>,
        leader_url: &Url,
        metric_updates: &[StatisticsUpdate],
    ) -> Result<(), anyhow::Error> {
        let leader_metric = statistics
            .get_mut(leader_url)
            .ok_or_else(|| anyhow::anyhow!("Leader URL is not present in statistics"))?;

        leader_metric.apply_updates(metric_updates);

        Ok(())
    }

    fn client_from_url_unchecked(url: &Url) -> SequencerClient {
        let builder = SequencerClientBuilder::default();
        builder.build(url).unwrap()
    }

    fn four_client_list() -> (Vec<(Url, SequencerClient)>, [Url; 4]) {
        let addr_leader = Url::parse("http://127.0.0.1:3040").unwrap();
        let addr_1 = Url::parse("http://127.0.0.1:3041").unwrap();
        let addr_2 = Url::parse("http://127.0.0.1:3042").unwrap();
        let addr_3 = Url::parse("http://127.0.0.1:3043").unwrap();

        let leader = client_from_url_unchecked(&addr_leader);
        let client_1 = client_from_url_unchecked(&addr_1);
        let client_2 = client_from_url_unchecked(&addr_2);
        let client_3 = client_from_url_unchecked(&addr_3);

        let client_list = vec![
            (addr_leader.clone(), leader),
            (addr_1.clone(), client_1),
            (addr_2.clone(), client_2),
            (addr_3.clone(), client_3),
        ];

        (client_list, [addr_leader, addr_1, addr_2, addr_3])
    }

    #[test]
    fn cumulative_updates_test() {
        let statistics_updates_vec = vec![
            StatisticsUpdate::Success {
                latency: 100_f32,
                new_latest_block_id: 15,
            },
            StatisticsUpdate::Success {
                latency: 115_f32,
                new_latest_block_id: 16,
            },
            StatisticsUpdate::Failure,
        ];

        let CumulativeUpdates {
            failure_count,
            latest_block_id,
            cumulative_latency,
            cumulative_latency_squares,
            additional_sample_size,
        } = CumulativeUpdates::from_metric_updates(&statistics_updates_vec);

        let epsilon = 0.01_f32;

        let sum_squared_manual = 100_f32.mul_add(100_f32, 115_f32 * 115_f32);

        assert_eq!(additional_sample_size, 2);
        assert_eq!(failure_count, 1);
        assert_eq!(latest_block_id, Some(16));
        assert!((cumulative_latency - 215_f32).abs() < epsilon);
        assert!((cumulative_latency_squares - sum_squared_manual).abs() < epsilon);
    }

    #[test]
    fn cumulative_avg_test() {
        let mut sample = vec![100_f32; 40];

        #[expect(clippy::as_conversions, reason = "int to float conversion is safe")]
        let old_sample_size_f = sample.len() as f32;

        let old_avg = sample.iter().sum::<f32>() / old_sample_size_f;

        let new_samples = vec![
            101_f32, 110_f32, 112_f32, 97_f32, 78_f32, 25_f32, 75_f32, 189_f32, 120_f32, 50_f32,
        ];

        #[expect(clippy::as_conversions, reason = "int to float conversion is safe")]
        let mod_sample_size_f = new_samples.len() as f32;

        let cumulative = new_samples.iter().sum();

        sample.extend_from_slice(&new_samples);

        #[expect(clippy::as_conversions, reason = "int to float conversion is safe")]
        let new_sample_size_f = sample.len() as f32;

        let new_avg_1 = sample.iter().sum::<f32>() / new_sample_size_f;

        let new_avg_2 = cumulative_avg(old_avg, cumulative, old_sample_size_f, mod_sample_size_f);

        let epsilon = 0.01_f32;

        assert!((new_avg_1 - new_avg_2).abs() < epsilon);
    }

    #[test]
    fn cumulative_var_test() {
        let mut sample = vec![100_f32; 40];

        #[expect(clippy::as_conversions, reason = "int to float conversion is safe")]
        let old_sample_size_f = sample.len() as f32;
        let old_avg = sample.iter().sum::<f32>() / old_sample_size_f;

        let old_var = sample
            .iter()
            .fold(0_f32, |acc, x| (x - old_avg).mul_add(x - old_avg, acc))
            / old_sample_size_f;

        let new_samples = vec![
            101_f32, 110_f32, 112_f32, 97_f32, 78_f32, 25_f32, 75_f32, 189_f32, 120_f32, 50_f32,
        ];

        #[expect(clippy::as_conversions, reason = "int to float conversion is safe")]
        let mod_sample_size_f = new_samples.len() as f32;

        let cumulative = new_samples.iter().sum();
        let cumulative_squares = new_samples
            .iter()
            .fold(0_f32, |acc, x| (*x).mul_add(*x, acc));

        let new_avg = cumulative_avg(old_avg, cumulative, old_sample_size_f, mod_sample_size_f);

        sample.extend_from_slice(&new_samples);

        #[expect(clippy::as_conversions, reason = "int to float conversion is safe")]
        let new_var_1 = sample
            .iter()
            .fold(0_f32, |acc, x| (x - new_avg).mul_add(x - new_avg, acc))
            / (sample.len() as f32);

        let new_var_2 = cumulative_var(
            old_avg,
            new_avg,
            old_var,
            cumulative,
            cumulative_squares,
            old_sample_size_f,
            mod_sample_size_f,
        );

        let epsilon = 0.01_f32;

        assert!((new_var_1 - new_var_2).abs() < epsilon);
    }

    #[test]
    fn metric_updates_correctness() {
        let statistics_updates_vec = vec![
            StatisticsUpdate::Success {
                latency: 100_f32,
                new_latest_block_id: 105,
            },
            StatisticsUpdate::Success {
                latency: 115_f32,
                new_latest_block_id: 106,
            },
            StatisticsUpdate::Failure,
        ];

        let addr_leader = Url::parse("https://127.0.0.1:3040").unwrap();

        let leader_statistics = Statistics {
            latency_avg: 100_f32,
            latency_var: 25_f32,
            sample_size: 10,
            latest_block_id: 100,
            errors: 5,
        };

        let cumulative_latency = 100_f32 + 115_f32;
        let cumulative_latency_squares = 100_f32.mul_add(100_f32, 115_f32 * 115_f32);

        let avg_manual = cumulative_avg(
            leader_statistics.latency_avg,
            cumulative_latency,
            10_f32,
            2_f32,
        );
        let var_manual = cumulative_var(
            leader_statistics.latency_avg,
            avg_manual,
            leader_statistics.latency_var,
            cumulative_latency,
            cumulative_latency_squares,
            10_f32,
            2_f32,
        );

        let mut metric_map = HashMap::new();
        metric_map.insert(addr_leader.clone(), leader_statistics);

        update_statistics(&mut metric_map, &addr_leader, &statistics_updates_vec).unwrap();

        let Statistics {
            latency_avg,
            latency_var,
            sample_size,
            latest_block_id,
            errors,
        } = metric_map[&addr_leader];

        let epsilon = 0.01_f32;

        assert_eq!(errors, 6);
        assert_eq!(latest_block_id, 106);
        assert_eq!(sample_size, 12);
        assert!((latency_avg - avg_manual).abs() < epsilon);
        assert!((latency_var - var_manual).abs() < epsilon);
    }

    #[test]
    fn choose_leader_latest_block() {
        let (client_list, [addr_leader, addr_1, addr_2, addr_3]) = four_client_list();

        let mut statistics = HashMap::new();

        statistics.insert(
            addr_3,
            Statistics {
                latency_avg: 100_f32,
                latency_var: 10_f32,
                sample_size: 10,
                latest_block_id: 97,
                errors: 5,
            },
        );

        statistics.insert(
            addr_2,
            Statistics {
                latency_avg: 100_f32,
                latency_var: 10_f32,
                sample_size: 10,
                latest_block_id: 98,
                errors: 5,
            },
        );

        statistics.insert(
            addr_1,
            Statistics {
                latency_avg: 100_f32,
                latency_var: 10_f32,
                sample_size: 10,
                latest_block_id: 99,
                errors: 5,
            },
        );

        statistics.insert(
            addr_leader.clone(),
            Statistics {
                latency_avg: 100_f32,
                latency_var: 10_f32,
                sample_size: 10,
                latest_block_id: 100,
                errors: 5,
            },
        );

        let leaders = choose_leaders(client_list, &statistics, 1).unwrap();

        let (_, leader_url) = leaders.first().unwrap();

        assert_eq!(leader_url, &addr_leader);
    }

    #[test]
    fn choose_leader_least_errors() {
        let (client_list, [addr_leader, addr_1, addr_2, addr_3]) = four_client_list();

        let mut statistics = HashMap::new();

        statistics.insert(
            addr_3,
            Statistics {
                latency_avg: 100_f32,
                latency_var: 10_f32,
                sample_size: 10,
                latest_block_id: 100,
                errors: 5,
            },
        );

        statistics.insert(
            addr_2,
            Statistics {
                latency_avg: 100_f32,
                latency_var: 10_f32,
                sample_size: 10,
                latest_block_id: 100,
                errors: 4,
            },
        );

        statistics.insert(
            addr_1,
            Statistics {
                latency_avg: 100_f32,
                latency_var: 10_f32,
                sample_size: 10,
                latest_block_id: 100,
                errors: 3,
            },
        );

        statistics.insert(
            addr_leader.clone(),
            Statistics {
                latency_avg: 100_f32,
                latency_var: 10_f32,
                sample_size: 10,
                latest_block_id: 100,
                errors: 2,
            },
        );

        let leaders = choose_leaders(client_list, &statistics, 1).unwrap();

        let (_, leader_url) = leaders.first().unwrap();

        assert_eq!(leader_url, &addr_leader);
    }

    #[test]
    fn choose_leader_simple_latency_check() {
        let (client_list, [addr_leader, addr_1, addr_2, addr_3]) = four_client_list();

        let mut statistics = HashMap::new();

        statistics.insert(
            addr_3,
            Statistics {
                latency_avg: 103_f32,
                latency_var: 10_f32,
                sample_size: 10,
                latest_block_id: 100,
                errors: 5,
            },
        );

        statistics.insert(
            addr_2,
            Statistics {
                latency_avg: 102_f32,
                latency_var: 10_f32,
                sample_size: 10,
                latest_block_id: 100,
                errors: 5,
            },
        );

        statistics.insert(
            addr_1,
            Statistics {
                latency_avg: 101_f32,
                latency_var: 10_f32,
                sample_size: 10,
                latest_block_id: 100,
                errors: 5,
            },
        );

        statistics.insert(
            addr_leader.clone(),
            Statistics {
                latency_avg: 100_f32,
                latency_var: 10_f32,
                sample_size: 10,
                latest_block_id: 100,
                errors: 5,
            },
        );

        let leaders = choose_leaders(client_list, &statistics, 1).unwrap();

        let (_, leader_url) = leaders.first().unwrap();

        assert_eq!(leader_url, &addr_leader);
    }

    #[test]
    fn choose_leader_latency_var_check() {
        let (client_list, [addr_leader, addr_1, addr_2, addr_3]) = four_client_list();

        let mut statistics = HashMap::new();

        statistics.insert(
            addr_3,
            Statistics {
                latency_avg: 100_f32,
                latency_var: 13_f32,
                sample_size: 10,
                latest_block_id: 100,
                errors: 5,
            },
        );

        statistics.insert(
            addr_2,
            Statistics {
                latency_avg: 100_f32,
                latency_var: 12_f32,
                sample_size: 10,
                latest_block_id: 100,
                errors: 5,
            },
        );

        statistics.insert(
            addr_1,
            Statistics {
                latency_avg: 100_f32,
                latency_var: 11_f32,
                sample_size: 10,
                latest_block_id: 100,
                errors: 5,
            },
        );

        statistics.insert(
            addr_leader.clone(),
            Statistics {
                latency_avg: 100_f32,
                latency_var: 10_f32,
                sample_size: 10,
                latest_block_id: 100,
                errors: 5,
            },
        );

        let leaders = choose_leaders(client_list, &statistics, 1).unwrap();

        let (_, leader_url) = leaders.first().unwrap();

        assert_eq!(leader_url, &addr_leader);
    }

    #[test]
    fn choose_multiple_leaders_latest_block() {
        let (client_list, [addr_leader, addr_1, addr_2, addr_3]) = four_client_list();

        let mut statistics = HashMap::new();

        statistics.insert(
            addr_3,
            Statistics {
                latency_avg: 100_f32,
                latency_var: 10_f32,
                sample_size: 10,
                latest_block_id: 97,
                errors: 5,
            },
        );

        statistics.insert(
            addr_2,
            Statistics {
                latency_avg: 100_f32,
                latency_var: 10_f32,
                sample_size: 10,
                latest_block_id: 98,
                errors: 5,
            },
        );

        statistics.insert(
            addr_1.clone(),
            Statistics {
                latency_avg: 100_f32,
                latency_var: 10_f32,
                sample_size: 10,
                latest_block_id: 100,
                errors: 5,
            },
        );

        statistics.insert(
            addr_leader.clone(),
            Statistics {
                latency_avg: 100_f32,
                latency_var: 10_f32,
                sample_size: 10,
                latest_block_id: 100,
                errors: 5,
            },
        );

        let leaders = choose_leaders(client_list, &statistics, 2).unwrap();

        let mut url_set_origin = HashSet::new();
        let mut url_set_res = HashSet::new();

        let (_, leader_url_first) = leaders[0].clone();
        let (_, leader_url_second) = leaders[1].clone();

        url_set_origin.insert(addr_leader);
        url_set_origin.insert(addr_1);

        url_set_res.insert(leader_url_first);
        url_set_res.insert(leader_url_second);

        assert_eq!(url_set_origin, url_set_res);
        assert_eq!(leaders.len(), 2);
    }

    #[test]
    fn choose_multiple_leaders_latest_block_still_chooses_one_best() {
        let (client_list, [addr_leader, addr_1, addr_2, addr_3]) = four_client_list();

        let mut statistics = HashMap::new();

        statistics.insert(
            addr_3,
            Statistics {
                latency_avg: 100_f32,
                latency_var: 10_f32,
                sample_size: 10,
                latest_block_id: 97,
                errors: 5,
            },
        );

        statistics.insert(
            addr_2,
            Statistics {
                latency_avg: 100_f32,
                latency_var: 10_f32,
                sample_size: 10,
                latest_block_id: 98,
                errors: 5,
            },
        );

        statistics.insert(
            addr_1,
            Statistics {
                latency_avg: 100_f32,
                latency_var: 10_f32,
                sample_size: 10,
                latest_block_id: 99,
                errors: 5,
            },
        );

        statistics.insert(
            addr_leader.clone(),
            Statistics {
                latency_avg: 100_f32,
                latency_var: 10_f32,
                sample_size: 10,
                latest_block_id: 100,
                errors: 5,
            },
        );

        let leaders = choose_leaders(client_list, &statistics, 2).unwrap();

        let (_, helm) = leaders.first().unwrap();

        assert_eq!(&addr_leader, helm);
        assert_eq!(leaders.len(), 1);
    }

    #[test]
    fn choose_multiple_leaders_least_errors() {
        let (client_list, [addr_leader, addr_1, addr_2, addr_3]) = four_client_list();

        let mut statistics = HashMap::new();

        statistics.insert(
            addr_3,
            Statistics {
                latency_avg: 100_f32,
                latency_var: 10_f32,
                sample_size: 10,
                latest_block_id: 100,
                errors: 6,
            },
        );

        statistics.insert(
            addr_2,
            Statistics {
                latency_avg: 100_f32,
                latency_var: 10_f32,
                sample_size: 10,
                latest_block_id: 100,
                errors: 6,
            },
        );

        statistics.insert(
            addr_1.clone(),
            Statistics {
                latency_avg: 100_f32,
                latency_var: 10_f32,
                sample_size: 10,
                latest_block_id: 100,
                errors: 3,
            },
        );

        statistics.insert(
            addr_leader.clone(),
            Statistics {
                latency_avg: 100_f32,
                latency_var: 10_f32,
                sample_size: 10,
                latest_block_id: 100,
                errors: 2,
            },
        );

        let leaders = choose_leaders(client_list, &statistics, 2).unwrap();

        let (_, leader_url_first) = leaders[0].clone();
        let (_, leader_url_second) = leaders[1].clone();

        assert_eq!(addr_leader, leader_url_first);
        assert_eq!(addr_1, leader_url_second);
        assert_eq!(leaders.len(), 2);
    }

    #[test]
    fn choose_multiple_leaders_simple_latency_check() {
        let (client_list, [addr_leader, addr_1, addr_2, addr_3]) = four_client_list();

        let mut statistics = HashMap::new();

        statistics.insert(
            addr_3,
            Statistics {
                latency_avg: 103_f32,
                latency_var: 10_f32,
                sample_size: 10,
                latest_block_id: 100,
                errors: 6,
            },
        );

        statistics.insert(
            addr_2,
            Statistics {
                latency_avg: 102_f32,
                latency_var: 10_f32,
                sample_size: 10,
                latest_block_id: 100,
                errors: 4,
            },
        );

        statistics.insert(
            addr_1.clone(),
            Statistics {
                latency_avg: 101_f32,
                latency_var: 10_f32,
                sample_size: 10,
                latest_block_id: 100,
                errors: 4,
            },
        );

        statistics.insert(
            addr_leader.clone(),
            Statistics {
                latency_avg: 100_f32,
                latency_var: 10_f32,
                sample_size: 10,
                latest_block_id: 100,
                errors: 4,
            },
        );

        let leaders = choose_leaders(client_list, &statistics, 2).unwrap();

        let (_, leader_url_first) = leaders[0].clone();
        let (_, leader_url_second) = leaders[1].clone();

        assert_eq!(addr_leader, leader_url_first);
        assert_eq!(addr_1, leader_url_second);
        assert_eq!(leaders.len(), 2);
    }

    #[test]
    fn choose_multiple_leaders_var_check() {
        let (client_list, [addr_leader, addr_1, addr_2, addr_3]) = four_client_list();

        let mut statistics = HashMap::new();

        statistics.insert(
            addr_3,
            Statistics {
                latency_avg: 103_f32,
                latency_var: 10_f32,
                sample_size: 10,
                latest_block_id: 100,
                errors: 6,
            },
        );

        statistics.insert(
            addr_2,
            Statistics {
                latency_avg: 100_f32,
                latency_var: 12_f32,
                sample_size: 10,
                latest_block_id: 100,
                errors: 4,
            },
        );

        statistics.insert(
            addr_1.clone(),
            Statistics {
                latency_avg: 100_f32,
                latency_var: 11_f32,
                sample_size: 10,
                latest_block_id: 100,
                errors: 4,
            },
        );

        statistics.insert(
            addr_leader.clone(),
            Statistics {
                latency_avg: 100_f32,
                latency_var: 10_f32,
                sample_size: 10,
                latest_block_id: 100,
                errors: 4,
            },
        );

        let leaders = choose_leaders(client_list, &statistics, 2).unwrap();

        let (_, leader_url_first) = leaders[0].clone();
        let (_, leader_url_second) = leaders[1].clone();

        assert_eq!(addr_leader, leader_url_first);
        assert_eq!(addr_1, leader_url_second);
        assert_eq!(leaders.len(), 2);
    }
}
