use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NumaNode {
    pub id: u32,
    /// Logical processor identifiers (Windows IDs are group * 64 + bit).
    pub cpus: Vec<usize>,
    pub memory_bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopologySource {
    LinuxSysfs,
    WindowsNumaApi,
    PortableFallback,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NumaTopology {
    pub nodes: Vec<NumaNode>,
    pub source: TopologySource,
    pub numa_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TopologyError {
    Discovery(String),
}

impl fmt::Display for TopologyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Discovery(s) => write!(f, "NUMA topology discovery failed: {s}"),
        }
    }
}
impl std::error::Error for TopologyError {}

impl NumaTopology {
    pub fn discover() -> Result<Self, TopologyError> {
        #[cfg(target_os = "linux")]
        {
            return linux::discover();
        }
        #[cfg(target_os = "windows")]
        {
            return windows::discover();
        }
        #[allow(unreachable_code)]
        Ok(Self::portable_fallback())
    }

    /// Explicit fallback for platforms without a native topology API, including WASM.
    pub fn portable_fallback() -> Self {
        let cpus = std::thread::available_parallelism()
            .map(|n| (0..n.get()).collect())
            .unwrap_or_default();
        Self {
            nodes: vec![NumaNode {
                id: 0,
                cpus,
                memory_bytes: None,
            }],
            source: TopologySource::PortableFallback,
            numa_enabled: false,
        }
    }

    pub fn node(&self, id: u32) -> Option<&NumaNode> {
        self.nodes.iter().find(|n| n.id == id)
    }
    pub fn total_logical_cpus(&self) -> usize {
        self.nodes.iter().map(|n| n.cpus.len()).sum()
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{NumaNode, NumaTopology, TopologyError, TopologySource};
    use std::{fs, path::Path};

    pub(super) fn discover() -> Result<NumaTopology, TopologyError> {
        let root = Path::new("/sys/devices/system/node");
        let entries = fs::read_dir(root).map_err(|e| {
            TopologyError::Discovery(format!("cannot read {}: {e}", root.display()))
        })?;
        let mut nodes = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| TopologyError::Discovery(e.to_string()))?;
            let name = entry.file_name();
            let Some(id_text) = name
                .to_string_lossy()
                .strip_prefix("node")
                .map(str::to_owned)
            else {
                continue;
            };
            let Ok(id) = id_text.parse::<u32>() else {
                continue;
            };
            let cpulist = fs::read_to_string(entry.path().join("cpulist"))
                .map_err(|e| TopologyError::Discovery(format!("node{id} cpulist: {e}")))?;
            let cpus = parse_cpu_list(cpulist.trim())?;
            let memory_bytes = fs::read_to_string(entry.path().join("meminfo"))
                .ok()
                .and_then(|text| {
                    text.lines().find_map(|line| {
                        let (_, rest) = line.split_once("MemTotal:")?;
                        rest.split_whitespace().next()?.parse::<u64>().ok()
                    })
                })
                .and_then(|kb| kb.checked_mul(1024));
            nodes.push(NumaNode {
                id,
                cpus,
                memory_bytes,
            });
        }
        nodes.sort_by_key(|n| n.id);
        if nodes.is_empty() {
            return Ok(NumaTopology::portable_fallback());
        }
        let numa_enabled = nodes.len() > 1;
        Ok(NumaTopology {
            nodes,
            source: TopologySource::LinuxSysfs,
            numa_enabled,
        })
    }

    fn parse_cpu_list(input: &str) -> Result<Vec<usize>, TopologyError> {
        let mut cpus = Vec::new();
        if input.is_empty() {
            return Ok(cpus);
        }
        for part in input.split(',') {
            let parsed = |s: &str| {
                s.parse::<usize>()
                    .map_err(|_| TopologyError::Discovery(format!("invalid CPU list: {input}")))
            };
            let (start, end) = match part.split_once('-') {
                Some((a, b)) => (parsed(a)?, parsed(b)?),
                None => {
                    let n = parsed(part)?;
                    (n, n)
                }
            };
            if end < start || end - start > 1_000_000 {
                return Err(TopologyError::Discovery(format!(
                    "invalid CPU range: {part}"
                )));
            }
            cpus.extend(start..=end);
        }
        cpus.sort_unstable();
        cpus.dedup();
        Ok(cpus)
    }

    #[cfg(test)]
    mod tests {
        use super::parse_cpu_list;
        #[test]
        fn parses_cpu_ranges() {
            assert_eq!(
                parse_cpu_list("0-3,8,10-11").unwrap(),
                vec![0, 1, 2, 3, 8, 10, 11]
            );
        }
        #[test]
        fn rejects_invalid_ranges() {
            assert!(parse_cpu_list("4-2").is_err());
        }
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use super::{NumaNode, NumaTopology, TopologyError, TopologySource};

    #[repr(C)]
    struct GroupAffinity {
        mask: usize,
        group: u16,
        reserved: [u16; 3],
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetNumaHighestNodeNumber(highest: *mut u32) -> i32;
        fn GetNumaNodeProcessorMaskEx(node: u16, affinity: *mut GroupAffinity) -> i32;
        fn GetNumaAvailableMemoryNodeEx(node: u16, available: *mut u64) -> i32;
    }

    pub(super) fn discover() -> Result<NumaTopology, TopologyError> {
        let mut highest = 0u32;
        // SAFETY: API receives a valid output pointer.
        if unsafe { GetNumaHighestNodeNumber(&mut highest) } == 0 {
            return Err(TopologyError::Discovery(
                "GetNumaHighestNodeNumber failed".into(),
            ));
        }
        let mut nodes = Vec::new();
        for id in 0..=highest.min(u16::MAX as u32) {
            let mut affinity = GroupAffinity {
                mask: 0,
                group: 0,
                reserved: [0; 3],
            };
            // SAFETY: affinity is a valid output buffer and id fits USHORT.
            if unsafe { GetNumaNodeProcessorMaskEx(id as u16, &mut affinity) } == 0 {
                continue;
            }
            let mut cpus = Vec::new();
            let mut mask = affinity.mask;
            while mask != 0 {
                let bit = mask.trailing_zeros() as usize;
                cpus.push(usize::from(affinity.group) * 64 + bit);
                mask &= mask - 1;
            }
            let mut memory = 0u64;
            let memory_bytes =
                if unsafe { GetNumaAvailableMemoryNodeEx(id as u16, &mut memory) } != 0 {
                    Some(memory)
                } else {
                    None
                };
            nodes.push(NumaNode {
                id,
                cpus,
                memory_bytes,
            });
        }
        if nodes.is_empty() {
            return Err(TopologyError::Discovery(
                "Windows returned no NUMA nodes".into(),
            ));
        }
        nodes.sort_by_key(|n| n.id);
        let numa_enabled = nodes.len() > 1;
        Ok(NumaTopology {
            nodes,
            source: TopologySource::WindowsNumaApi,
            numa_enabled,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{NumaTopology, TopologySource};
    #[test]
    fn portable_fallback_is_explicit() {
        let topology = NumaTopology::portable_fallback();
        assert_eq!(topology.source, TopologySource::PortableFallback);
        assert!(!topology.numa_enabled);
        assert_eq!(topology.nodes.len(), 1);
    }
    #[test]
    fn topology_queries_are_consistent() {
        let topology = NumaTopology::portable_fallback();
        assert_eq!(topology.node(0).map(|n| n.id), Some(0));
        assert_eq!(topology.total_logical_cpus(), topology.nodes[0].cpus.len());
        assert!(topology.node(99).is_none());
    }
}
