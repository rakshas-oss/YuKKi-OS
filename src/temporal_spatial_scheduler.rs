//! Time-weighted spatial selection for replicas of a live program.
//!
//! A spatial key (tenant, tile, sensor, partition, or other stable workload key)
//! identifies a preferred replica. Recent service time is an exponentially
//! weighted moving average. The preferred replica receives a small locality
//! preference, but a materially faster replica can win instead. Callers must
//! still perform non-blocking admission; this scheduler never waits on a busy
//! replica and does not promise physical NUMA pinning.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

const DEFAULT_SERVICE_TIME_NS: u64 = 1_000_000;
const LOCALITY_PENALTY_DIVISOR: u64 = 4;

/// Time-weighted measurements for one execution replica.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplicaTimingSnapshot {
    pub replica_index: usize,
    pub service_time_ewma_ns: u64,
    pub completed_calls: u64,
}

struct ReplicaTiming {
    service_time_ewma_ns: AtomicU64,
    completed_calls: AtomicU64,
}

/// Ranks replica candidates using recent execution time and an optional
/// stable spatial/affinity key. It is deliberately independent of Wasmtime.
pub struct TimeWeightedSpatialScheduler {
    replicas: Vec<ReplicaTiming>,
    cursor: AtomicUsize,
}

impl TimeWeightedSpatialScheduler {
    /// Create a scheduler for a fixed, non-zero replica set.
    pub fn new(replica_count: usize) -> Result<Self, &'static str> {
        if replica_count == 0 {
            return Err("replica_count must be greater than zero");
        }
        Ok(Self {
            replicas: (0..replica_count)
                .map(|_| ReplicaTiming {
                    service_time_ewma_ns: AtomicU64::new(DEFAULT_SERVICE_TIME_NS),
                    completed_calls: AtomicU64::new(0),
                })
                .collect(),
            cursor: AtomicUsize::new(0),
        })
    }

    /// Return candidates from best predicted service time to worst.
    ///
    /// The spatial key sets a preferred logical shard. That preference is a
    /// tie-break/locality hint, not a pin: time-weighted service cost can route
    /// around a slow replica.
    pub fn ranked_candidates(&self, spatial_key: Option<u64>) -> Vec<usize> {
        self.ranked_candidates_with_load(spatial_key, &[])
    }

    /// Rank replicas by estimated service cost multiplied by current active
    /// load, with a bounded preference for stable spatial locality. Missing
    /// load entries are treated as zero so callers can use partial telemetry.
    pub fn ranked_candidates_with_load(
        &self,
        spatial_key: Option<u64>,
        active_calls: &[usize],
    ) -> Vec<usize> {
        let count = self.replicas.len();
        let cursor = self.cursor.fetch_add(1, Ordering::Relaxed) % count;
        let preferred = spatial_key.map(|key| spatial_slot(key, count));
        let mut ranked: Vec<(u64, usize, usize)> = self
            .replicas
            .iter()
            .enumerate()
            .map(|(index, timing)| {
                let estimate = timing.service_time_ewma_ns.load(Ordering::Relaxed);
                let active = active_calls.get(index).copied().unwrap_or(0);
                let concurrency_cost = estimate
                    .saturating_mul(u64::try_from(active).unwrap_or(u64::MAX).saturating_add(1));
                let locality_penalty = if preferred.is_some_and(|slot| slot != index) {
                    estimate / LOCALITY_PENALTY_DIVISOR
                } else {
                    0
                };
                let tie_break = (index + count - cursor) % count;
                (
                    concurrency_cost.saturating_add(locality_penalty),
                    tie_break,
                    index,
                )
            })
            .collect();
        ranked.sort_unstable();
        ranked.into_iter().map(|(_, _, index)| index).collect()
    }

    /// Record one completed invocation and update its decaying service-time
    /// estimate. Failed invocations count too, since they consumed service time.
    pub fn record_completion(&self, replica_index: usize, elapsed: Duration) {
        let Some(timing) = self.replicas.get(replica_index) else {
            return;
        };
        let sample = elapsed.as_nanos().min(u64::MAX as u128) as u64;
        let sample = sample.max(1);
        let estimate = &timing.service_time_ewma_ns;
        let mut previous = estimate.load(Ordering::Relaxed);
        loop {
            // 7/8 history + 1/8 new sample, calculated without overflowing.
            let updated = previous
                .saturating_sub(previous / 8)
                .saturating_add(sample / 8);
            match estimate.compare_exchange_weak(
                previous,
                updated.max(1),
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => previous = actual,
            }
        }
        timing.completed_calls.fetch_add(1, Ordering::Relaxed);
    }

    /// Snapshot timing data for diagnostics and benchmark feedback.
    pub fn metrics(&self) -> Vec<ReplicaTimingSnapshot> {
        self.replicas
            .iter()
            .enumerate()
            .map(|(replica_index, timing)| ReplicaTimingSnapshot {
                replica_index,
                service_time_ewma_ns: timing.service_time_ewma_ns.load(Ordering::Relaxed),
                completed_calls: timing.completed_calls.load(Ordering::Relaxed),
            })
            .collect()
    }
}

fn spatial_slot(key: u64, replica_count: usize) -> usize {
    // SplitMix64 finalizer: stable across processes and independent of Rust's
    // randomized HashMap hasher.
    let mut value = key;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d049bb133111eb);
    value ^= value >> 31;
    (value as usize) % replica_count
}

#[cfg(test)]
mod tests {
    use super::TimeWeightedSpatialScheduler;
    use std::time::Duration;

    #[test]
    fn stable_spatial_key_prefers_same_logical_replica() {
        let scheduler = TimeWeightedSpatialScheduler::new(4).unwrap();
        let first = scheduler.ranked_candidates(Some(0x1234))[0];
        for _ in 0..8 {
            let ranked = scheduler.ranked_candidates(Some(0x1234));
            assert_eq!(ranked[0], first);
        }
    }

    #[test]
    fn time_weighted_measurement_can_override_locality() {
        let scheduler = TimeWeightedSpatialScheduler::new(2).unwrap();
        let preferred = scheduler.ranked_candidates(Some(1))[0];
        let other = 1 - preferred;
        for _ in 0..64 {
            scheduler.record_completion(preferred, Duration::from_millis(40));
            scheduler.record_completion(other, Duration::from_micros(100));
        }
        assert_eq!(scheduler.ranked_candidates(Some(1))[0], other);
    }

    #[test]
    fn active_replica_load_can_override_spatial_preference() {
        let scheduler = TimeWeightedSpatialScheduler::new(2).unwrap();
        let preferred = scheduler.ranked_candidates(Some(7))[0];
        let other = 1 - preferred;
        assert_eq!(
            scheduler.ranked_candidates_with_load(Some(7), &[0, 0])[0],
            preferred
        );
        let mut loads = vec![0usize; 2];
        loads[preferred] = 8;
        assert_eq!(
            scheduler.ranked_candidates_with_load(Some(7), &loads)[0],
            other
        );
    }

    #[test]
    fn timing_metrics_count_success_and_failure_completions() {
        let scheduler = TimeWeightedSpatialScheduler::new(2).unwrap();
        scheduler.record_completion(1, Duration::from_micros(250));
        let metrics = scheduler.metrics();
        assert_eq!(metrics[0].completed_calls, 0);
        assert_eq!(metrics[1].completed_calls, 1);
        assert!(metrics[1].service_time_ewma_ns < metrics[0].service_time_ewma_ns);
    }

    #[test]
    fn zero_replicas_are_rejected() {
        assert!(TimeWeightedSpatialScheduler::new(0).is_err());
    }
}
