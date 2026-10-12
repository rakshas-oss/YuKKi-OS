#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct MeshNode {
    pub id: String,
    pub name: String,
    pub lat: f64,
    pub lon: f64,
    pub alt: Option<f64>,
    pub heading: Option<f64>,
    pub rssi_dbm: Option<i32>,
    pub latency_ms: Option<u32>,
    pub status: String,
    pub neighbors: Vec<String>,
    pub stream_id: Option<String>,
    pub updated_at: u64,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct MeshSnapshot {
    pub nodes: Vec<MeshNode>,
    pub generated_at: u64,
}

#[cfg(feature = "mesh_dashboard")]
use rstar::{AABB, RTree, RTreeObject};

#[cfg(feature = "mesh_dashboard")]
#[derive(Clone)]
pub struct MeshPoint {
    pub node: MeshNode,
}

#[cfg(feature = "mesh_dashboard")]
impl RTreeObject for MeshPoint {
    type Envelope = AABB<[f64; 2]>;

    fn envelope(&self) -> Self::Envelope {
        AABB::from_corners([self.node.lon, self.node.lat], [self.node.lon, self.node.lat])
    }
}

#[derive(Clone, Default)]
pub struct MeshStore {
    nodes: Arc<RwLock<HashMap<String, MeshNode>>>,
    #[cfg(feature = "mesh_dashboard")]
    rtree: Arc<RwLock<RTree<MeshPoint>>>,
}

impl MeshStore {
    pub fn new() -> Self {
        Self {
            nodes: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(feature = "mesh_dashboard")]
            rtree: Arc::new(RwLock::new(RTree::new())),
        }
    }

    pub fn upsert_node(&self, node: MeshNode) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut nodes = self.nodes.write().unwrap();
        nodes.insert(node.id.clone(), node.clone());
        #[cfg(feature = "mesh_dashboard")]
        {
            let mut rtree = self.rtree.write().unwrap();
            rtree.insert(MeshPoint { node: node.clone() });
            // retain only the newest version for each id; this is a simple, obvious approach
            let stale: Vec<String> = nodes
                .iter()
                .filter(|(_, candidate)| candidate.updated_at < now)
                .map(|(id, _)| id.clone())
                .collect();
            for id in stale {
                let _ = nodes.remove(&id);
            }
        }
    }

    pub fn snapshot(&self) -> MeshSnapshot {
        let nodes = self.nodes.read().unwrap();
        let mut ordered: Vec<MeshNode> = nodes.values().cloned().collect();
        ordered.sort_by(|a, b| a.id.cmp(&b.id));
        let generated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        MeshSnapshot {
            nodes: ordered,
            generated_at,
        }
    }

    #[cfg(feature = "mesh_dashboard")]
    pub fn query_bbox(
        &self,
        min_lon: f64,
        min_lat: f64,
        max_lon: f64,
        max_lat: f64,
        limit: usize,
        since: Option<u64>,
    ) -> Vec<MeshNode> {
        let tree = self.rtree.read().unwrap();
        let envelope = AABB::from_corners([min_lon, min_lat], [max_lon, max_lat]);
        let mut out = Vec::new();
        for item in tree.locate_in_envelope_intersecting(&envelope) {
            let node = item.node.clone();
            if let Some(since) = since {
                if node.updated_at <= since {
                    continue;
                }
            }
            out.push(node);
            if out.len() >= limit {
                break;
            }
        }
        out
    }
}

pub fn demo_mesh_nodes() -> Vec<MeshNode> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let ids = ["drone-a1", "drone-a2", "drone-a3", "drone-a4", "drone-a5", "drone-a6"];
    let base_lat = 37.7749;
    let base_lon = -122.4194;

    ids.iter()
        .enumerate()
        .map(|(idx, id)| MeshNode {
            id: id.to_string(),
            name: format!("Drone {}", idx + 1),
            lat: base_lat + (idx as f64) * 0.0017,
            lon: base_lon + (idx as f64) * 0.0012,
            alt: Some(110.0 + idx as f64 * 6.0),
            heading: Some((idx as f64 * 32.0) % 360.0),
            rssi_dbm: Some(-64 - idx as i32),
            latency_ms: Some(12 + idx as u32 * 5),
            status: "online".to_string(),
            neighbors: match idx {
                0 => vec![ids[1].to_string()],
                1 => vec![ids[0].to_string(), ids[2].to_string()],
                2 => vec![ids[1].to_string(), ids[3].to_string()],
                3 => vec![ids[2].to_string(), ids[4].to_string()],
                4 => vec![ids[3].to_string(), ids[5].to_string()],
                _ => vec![ids[4].to_string()],
            },
            stream_id: Some(format!("stream-{}", idx + 1)),
            updated_at: now,
        })
        .collect()
}
