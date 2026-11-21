//! YuKKi-OS workload intent for heterogeneous broker worker pools.
//!
//! YuKKi-OS owns classification. Overhauled consumes the directive to choose
//! a local worker pool and apply local CPU/accelerator placement. The
//! directive is carried only as optional BRK2 TLVs; it does not alter WSM1,
//! BRK1, or BRK2 envelope identities.

use serde::{Deserialize, Serialize};

use crate::exec_policy::TaskProfile;
use crate::spatiotemporal_resolver::ResolvedPayload;

/// Scheduling class selected by YuKKi-OS from workload semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkerClass {
    /// Lifecycle, protocol, and coordination work.
    Control,
    /// Time-sensitive spatial streams and ordered observations.
    RealtimeSpatial,
    /// Dataset and batch-oriented work.
    Throughput,
    /// CPU-only exactness, cryptographic, or verification-sensitive work.
    ExactCpu,
    /// Model inference eligible for backend policy evaluation.
    Inference,
}

impl WorkerClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::RealtimeSpatial => "realtime-spatial",
            Self::Throughput => "throughput",
            Self::ExactCpu => "exact-cpu",
            Self::Inference => "inference",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "control" => Some(Self::Control),
            "realtime-spatial" => Some(Self::RealtimeSpatial),
            "throughput" => Some(Self::Throughput),
            "exact-cpu" => Some(Self::ExactCpu),
            "inference" => Some(Self::Inference),
            _ => None,
        }
    }
}

/// Explicit scheduling intent to attach to a BRK2 request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerDirective {
    pub worker_class: WorkerClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spatial_affinity_key: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_numa_node: Option<u32>,
    /// Absolute Unix deadline in nanoseconds. Zero is invalid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_unix_ns: Option<u64>,
}

impl Default for WorkerDirective {
    fn default() -> Self {
        Self::throughput()
    }
}

impl WorkerDirective {
    pub const fn control() -> Self {
        Self {
            worker_class: WorkerClass::Control,
            spatial_affinity_key: None,
            preferred_numa_node: None,
            deadline_unix_ns: None,
        }
    }

    pub const fn realtime_spatial(
        spatial_affinity_key: u64,
        preferred_numa_node: Option<u32>,
        deadline_unix_ns: Option<u64>,
    ) -> Self {
        Self {
            worker_class: WorkerClass::RealtimeSpatial,
            spatial_affinity_key: Some(spatial_affinity_key),
            preferred_numa_node,
            deadline_unix_ns,
        }
    }

    pub const fn throughput() -> Self {
        Self {
            worker_class: WorkerClass::Throughput,
            spatial_affinity_key: None,
            preferred_numa_node: None,
            deadline_unix_ns: None,
        }
    }

    pub const fn exact_cpu() -> Self {
        Self {
            worker_class: WorkerClass::ExactCpu,
            spatial_affinity_key: None,
            preferred_numa_node: None,
            deadline_unix_ns: None,
        }
    }

    pub const fn inference() -> Self {
        Self {
            worker_class: WorkerClass::Inference,
            spatial_affinity_key: None,
            preferred_numa_node: None,
            deadline_unix_ns: None,
        }
    }

    /// Build a deterministic stream-affinity hint from a resolved NXR1 route.
    /// The key identifies a logical source/destination stream, not a geographic
    /// coordinate or physical CPU. The resolver's NUMA value remains advisory.
    pub fn for_resolved_spatial_payload(
        payload: &ResolvedPayload,
        deadline_unix_ns: Option<u64>,
    ) -> Self {
        let mut hash = 0xcbf29ce484222325u64;
        for byte in payload
            .source
            .bytes()
            .chain([0xff])
            .chain(payload.destination.bytes())
        {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        Self::realtime_spatial(hash, payload.numa_node, deadline_unix_ns)
    }

    /// Derive worker scheduling intent from YuKKi-OS's existing task profile.
    ///
    /// `now_unix_ns` is captured immediately before submission. A relative
    /// TaskProfile deadline is converted to the absolute Unix-nanosecond value
    /// carried by BRK2. Exact-precision requirements take precedence over
    /// spatial scheduling; their affinity and NUMA hints are still retained.
    /// A spatial route otherwise selects RealtimeSpatial, then Inference or
    /// Throughput follows the task profile. Backend preference remains a
    /// separate BRK2 device-preference decision.
    pub fn for_task_profile(
        profile: &TaskProfile,
        now_unix_ns: u64,
        spatial: Option<&ResolvedPayload>,
    ) -> Result<Self, &'static str> {
        if now_unix_ns == 0 || now_unix_ns > i64::MAX as u64 {
            return Err("now_unix_ns is outside the supported Unix-nanosecond range");
        }
        let deadline_unix_ns = match profile.deadline_ms {
            Some(0) => return Err("TaskProfile deadline_ms must be nonzero"),
            Some(milliseconds) => {
                let delta = milliseconds
                    .checked_mul(1_000_000)
                    .ok_or("TaskProfile deadline_ms overflows nanoseconds")?;
                Some(
                    now_unix_ns
                        .checked_add(delta)
                        .filter(|deadline| *deadline <= i64::MAX as u64)
                        .ok_or("absolute task deadline is outside the supported range")?,
                )
            }
            None => None,
        };

        let mut directive = if profile.requires_exact_precision {
            Self::exact_cpu()
        } else if let Some(payload) = spatial {
            Self::for_resolved_spatial_payload(payload, deadline_unix_ns)
        } else if profile.is_inference {
            Self::inference()
        } else {
            // Data-parallel and generic CPU-first work use the Throughput
            // queue; Overhauled may still select a GPU from local policy.
            Self::throughput()
        };

        // The relative TaskProfile deadline applies to every worker class,
        // not only spatial and exact-precision directives.
        directive.deadline_unix_ns = deadline_unix_ns;

        if profile.requires_exact_precision {
            if let Some(payload) = spatial {
                let spatial_hint = Self::for_resolved_spatial_payload(payload, deadline_unix_ns);
                directive.spatial_affinity_key = spatial_hint.spatial_affinity_key;
                directive.preferred_numa_node = spatial_hint.preferred_numa_node;
            }
        }
        directive.validate()?;
        Ok(directive)
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.deadline_unix_ns == Some(0) {
            return Err("deadline_unix_ns must be nonzero");
        }
        if self
            .deadline_unix_ns
            .is_some_and(|deadline| deadline > i64::MAX as u64)
        {
            return Err("deadline_unix_ns exceeds the supported signed clock range");
        }
        if self
            .deadline_unix_ns
            .is_some_and(|value| value > i64::MAX as u64)
        {
            return Err("deadline_unix_ns exceeds the supported Unix clock range");
        }
        if self.worker_class == WorkerClass::RealtimeSpatial && self.spatial_affinity_key.is_none()
        {
            return Err("realtime-spatial directives require a spatial_affinity_key");
        }
        Ok(())
    }
}

/// Execution telemetry returned by an Overhauled BRK2 response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerTelemetry {
    pub worker_class: WorkerClass,
    pub queue_wait_us: u64,
    pub service_time_us: u64,
    pub worker_id: u32,
    /// Present only when the broker successfully applied Linux CPU affinity.
    pub numa_node: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_class_names_are_stable() {
        for class in [
            WorkerClass::Control,
            WorkerClass::RealtimeSpatial,
            WorkerClass::Throughput,
            WorkerClass::ExactCpu,
            WorkerClass::Inference,
        ] {
            assert_eq!(WorkerClass::parse(class.as_str()), Some(class));
        }
        assert_eq!(WorkerClass::parse("not-a-class"), None);
    }

    #[test]
    fn realtime_directive_requires_logical_affinity() {
        let directive = WorkerDirective {
            worker_class: WorkerClass::RealtimeSpatial,
            spatial_affinity_key: None,
            preferred_numa_node: Some(2),
            deadline_unix_ns: Some(1),
        };
        assert!(directive.validate().is_err());
    }

    #[test]
    fn directive_rejects_deadline_outside_signed_unix_nanosecond_range() {
        let mut directive = WorkerDirective::inference();
        directive.deadline_unix_ns = Some(u64::MAX);
        assert!(directive.validate().is_err());
    }

    #[test]
    fn task_profile_selects_worker_class_and_absolute_deadline() {
        let profile = TaskProfile {
            is_data_parallel: true,
            deadline_ms: Some(250),
            ..TaskProfile::default()
        };
        let directive = WorkerDirective::for_task_profile(&profile, 1_000_000_000, None).unwrap();
        assert_eq!(directive.worker_class, WorkerClass::Throughput);
        assert_eq!(directive.deadline_unix_ns, Some(1_250_000_000));

        let inference = TaskProfile {
            is_inference: true,
            deadline_ms: Some(250),
            ..TaskProfile::default()
        };
        let inference_directive =
            WorkerDirective::for_task_profile(&inference, 1_000, None).unwrap();
        assert_eq!(inference_directive.worker_class, WorkerClass::Inference);
        assert_eq!(inference_directive.deadline_unix_ns, Some(250_001_000));
    }

    #[test]
    fn spatial_context_selects_realtime_unless_exact_cpu_is_required() {
        let payload = ResolvedPayload {
            source: "sensor-a".into(),
            destination: "physics".into(),
            numa_node: Some(2),
            frame: crate::nxr1::Nxr1Frame {
                seq_id: 1,
                x: 0.0,
                y: 0.0,
                z: 0.0,
                u: 0.0,
                v: 0.0,
                w: 0.0,
                fluidity: 0.0,
                drag: 0.0,
                divergence: 0.0,
                payload: vec![],
            },
        };
        let profile = TaskProfile {
            deadline_ms: Some(100),
            ..TaskProfile::default()
        };
        let directive =
            WorkerDirective::for_task_profile(&profile, 5_000_000, Some(&payload)).unwrap();
        assert_eq!(directive.worker_class, WorkerClass::RealtimeSpatial);
        assert_eq!(directive.preferred_numa_node, Some(2));
        assert_eq!(directive.deadline_unix_ns, Some(105_000_000));

        let exact = TaskProfile {
            requires_exact_precision: true,
            ..profile
        };
        let exact_directive =
            WorkerDirective::for_task_profile(&exact, 5_000_000, Some(&payload)).unwrap();
        assert_eq!(exact_directive.worker_class, WorkerClass::ExactCpu);
        assert!(exact_directive.spatial_affinity_key.is_some());
        assert_eq!(exact_directive.preferred_numa_node, Some(2));
    }

    #[test]
    fn task_profile_rejects_invalid_relative_deadline() {
        let zero = TaskProfile {
            deadline_ms: Some(0),
            ..TaskProfile::default()
        };
        assert!(WorkerDirective::for_task_profile(&zero, 1, None).is_err());
        let overflow = TaskProfile {
            deadline_ms: Some(u64::MAX),
            ..TaskProfile::default()
        };
        assert!(WorkerDirective::for_task_profile(&overflow, 1, None).is_err());
    }

    #[test]
    fn spatial_payload_directive_keeps_resolver_numa_hint() {
        let payload = ResolvedPayload {
            source: "sensor-a".into(),
            destination: "physics".into(),
            numa_node: Some(3),
            frame: crate::nxr1::Nxr1Frame {
                seq_id: 7,
                x: 1.0,
                y: 2.0,
                z: 3.0,
                u: 0.0,
                v: 0.0,
                w: 0.0,
                fluidity: 0.0,
                drag: 0.0,
                divergence: 0.0,
                payload: vec![],
            },
        };
        let directive = WorkerDirective::for_resolved_spatial_payload(&payload, Some(99));
        assert_eq!(directive.worker_class, WorkerClass::RealtimeSpatial);
        assert_eq!(directive.preferred_numa_node, Some(3));
        assert_eq!(directive.deadline_unix_ns, Some(99));
        assert!(directive.spatial_affinity_key.is_some());
    }
}
