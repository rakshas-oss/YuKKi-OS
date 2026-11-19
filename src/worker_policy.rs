//! YuKKi-OS workload intent for heterogeneous broker worker pools.
//!
//! YuKKi-OS owns classification. Overhauled consumes the directive to choose
//! a local worker pool and apply local CPU/accelerator placement. The
//! directive is carried only as optional BRK2 TLVs; it does not alter WSM1,
//! BRK1, or BRK2 envelope identities.

use serde::{Deserialize, Serialize};

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
        for byte in payload.source.bytes().chain([0xff]).chain(payload.destination.bytes()) {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        Self::realtime_spatial(hash, payload.numa_node, deadline_unix_ns)
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.deadline_unix_ns == Some(0) {
            return Err("deadline_unix_ns must be nonzero");
        }
        if self.deadline_unix_ns.is_some_and(|value| value > i64::MAX as u64) {
            return Err("deadline_unix_ns exceeds the supported Unix clock range");
        }
        if self.worker_class == WorkerClass::RealtimeSpatial && self.spatial_affinity_key.is_none() {
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
    fn spatial_payload_directive_keeps_resolver_numa_hint() {
        let payload = ResolvedPayload {
            source: "sensor-a".into(),
            destination: "physics".into(),
            numa_node: Some(3),
            frame: crate::nxr1::Nxr1Frame {
                seq_id: 7, x: 1.0, y: 2.0, z: 3.0, u: 0.0, v: 0.0, w: 0.0,
                fluidity: 0.0, drag: 0.0, divergence: 0.0, payload: vec![],
            },
        };
        let directive = WorkerDirective::for_resolved_spatial_payload(&payload, Some(99));
        assert_eq!(directive.worker_class, WorkerClass::RealtimeSpatial);
        assert_eq!(directive.preferred_numa_node, Some(3));
        assert_eq!(directive.deadline_unix_ns, Some(99));
        assert!(directive.spatial_affinity_key.is_some());
    }
}
