//! CPU-first execution policy: CPU is the always-available baseline and
//! accelerators (GPU/NPU/remote peers) are optional, best-effort escalation tiers.

use std::env;

/// Execution backends in escalation order. `Cpu` is always available.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExecutionBackend {
    Cpu,
    Gpu,
    Npu,
    Remote,
}

/// Requirements of a task, used to decide whether acceleration is justified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskProfile {
    /// Exact / verification-sensitive (e.g. PQC, integrity checks): CPU only.
    pub requires_exact_precision: bool,
    pub is_inference: bool,
    pub is_data_parallel: bool,
    pub estimated_bytes: usize,
    pub estimated_flops: u64,
    pub deadline_ms: Option<u64>,
    /// Whether re-running on CPU after an accelerator failure is semantically safe.
    pub cpu_retry_safe: bool,
}

impl Default for TaskProfile {
    fn default() -> Self {
        Self {
            requires_exact_precision: false,
            is_inference: false,
            is_data_parallel: false,
            estimated_bytes: 0,
            estimated_flops: 0,
            deadline_ms: None,
            cpu_retry_safe: true,
        }
    }
}

/// Which optional backends are currently usable.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BackendAvailability {
    pub gpu: bool,
    pub npu: bool,
    pub remote: bool,
}

/// Explicit backend selection policy. The default never selects an accelerator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackendPolicy {
    /// When false, every task runs on CPU (`YUKKI_FORCE_CPU_FALLBACK=true`).
    pub accelerators_allowed: bool,
    /// Minimum payload size for data-parallel offload to GPU.
    pub offload_threshold_bytes: usize,
}

impl BackendPolicy {
    pub const DEFAULT_OFFLOAD_THRESHOLD_BYTES: usize = 16 * 1024;
    pub const FORCE_CPU_ENV: &'static str = "YUKKI_FORCE_CPU_FALLBACK";

    pub fn from_env() -> Self {
        let force_cpu = env::var(Self::FORCE_CPU_ENV)
            .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);
        Self {
            accelerators_allowed: !force_cpu,
            ..Self::default()
        }
    }

    pub fn cpu_only() -> Self {
        Self {
            accelerators_allowed: false,
            ..Self::default()
        }
    }

    /// Choose the primary backend for a task. Exact-precision work is always CPU.
    pub fn select(&self, profile: &TaskProfile, avail: BackendAvailability) -> ExecutionBackend {
        if profile.requires_exact_precision || !self.accelerators_allowed {
            return ExecutionBackend::Cpu;
        }
        if profile.is_inference && avail.npu {
            return ExecutionBackend::Npu;
        }
        if profile.is_data_parallel
            && profile.estimated_bytes >= self.offload_threshold_bytes
            && avail.gpu
        {
            return ExecutionBackend::Gpu;
        }
        ExecutionBackend::Cpu
    }

    /// Ordered attempt chain; always ends with `Cpu` unless a CPU retry is unsafe
    /// after an accelerator was chosen (then the accelerator is the only attempt).
    pub fn chain(
        &self,
        profile: &TaskProfile,
        avail: BackendAvailability,
    ) -> Vec<ExecutionBackend> {
        match self.select(profile, avail) {
            ExecutionBackend::Cpu => vec![ExecutionBackend::Cpu],
            primary if profile.cpu_retry_safe => vec![primary, ExecutionBackend::Cpu],
            primary => vec![primary],
        }
    }
}

impl Default for BackendPolicy {
    fn default() -> Self {
        Self {
            accelerators_allowed: true,
            offload_threshold_bytes: Self::DEFAULT_OFFLOAD_THRESHOLD_BYTES,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parallel() -> TaskProfile {
        TaskProfile {
            is_data_parallel: true,
            estimated_bytes: 1 << 20,
            ..TaskProfile::default()
        }
    }

    #[test]
    fn cpu_when_no_accelerators() {
        let p = BackendPolicy::default();
        assert_eq!(
            p.select(&parallel(), BackendAvailability::default()),
            ExecutionBackend::Cpu
        );
    }

    #[test]
    fn gpu_for_large_parallel_and_cpu_for_small() {
        let p = BackendPolicy::default();
        let a = BackendAvailability {
            gpu: true,
            ..Default::default()
        };
        assert_eq!(p.select(&parallel(), a), ExecutionBackend::Gpu);
        let small = TaskProfile {
            estimated_bytes: 8,
            ..parallel()
        };
        assert_eq!(p.select(&small, a), ExecutionBackend::Cpu);
    }

    #[test]
    fn exact_precision_never_offloads() {
        let a = BackendAvailability {
            gpu: true,
            npu: true,
            remote: true,
        };
        let t = TaskProfile {
            requires_exact_precision: true,
            is_inference: true,
            ..parallel()
        };
        assert_eq!(
            BackendPolicy::default().chain(&t, a),
            vec![ExecutionBackend::Cpu]
        );
    }
}
