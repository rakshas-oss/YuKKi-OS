#![allow(dead_code)]
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct MeshNode {
    pub id: String, pub name: String, pub lat: f64, pub lon: f64,
    pub alt: Option<f64>, pub heading: Option<f64>, pub rssi_dbm: Option<i32>,
    pub latency_ms: Option<u32>, pub status: String, pub neighbors: Vec<String>,
    pub stream_id: Option<String>, pub updated_at: u64,
}
#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct MeshSnapshot { pub nodes: Vec<MeshNode>, pub generated_at: u64 }

#[cfg(feature = "mesh_dashboard")]
use rstar::{AABB, RTree, RTreeObject};
#[cfg(feature = "mesh_dashboard")]
#[derive(Clone)]
pub struct MeshPoint { pub node: MeshNode }
#[cfg(feature = "mesh_dashboard")]
impl PartialEq for MeshPoint {
    fn eq(&self, other: &Self) -> bool { self.node.id == other.node.id }
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
        if !node.lat.is_finite() || !node.lon.is_finite() {
            return;
        }
        let mut nodes = self.nodes.write().unwrap();
        let previous = nodes.insert(node.id.clone(), node.clone());
        #[cfg(feature = "mesh_dashboard")]
        {
            let mut rtree = self.rtree.write().unwrap();
            if let Some(previous) = previous {
                let removed = rtree.remove(&MeshPoint { node: previous });
                debug_assert!(removed.is_some(), "mesh map and RTree must stay in sync");
            }
            rtree.insert(MeshPoint { node });
        }
        #[cfg(not(feature = "mesh_dashboard"))]
        let _ = previous;
    }
    pub fn snapshot(&self) -> MeshSnapshot {
        let nodes = self.nodes.read().unwrap();
        let mut ordered: Vec<MeshNode> = nodes.values().cloned().collect();
        ordered.sort_by(|a, b| a.id.cmp(&b.id));
        let generated_at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        MeshSnapshot { nodes: ordered, generated_at }
    }
    #[cfg(feature = "mesh_dashboard")]
    pub fn query_bbox(&self, min_lon: f64, min_lat: f64, max_lon: f64, max_lat: f64,
        limit: usize, since: Option<u64>) -> Vec<MeshNode> {
        if limit == 0 || min_lon > max_lon || min_lat > max_lat { return Vec::new(); }
        let tree = self.rtree.read().unwrap();
        let envelope = AABB::from_corners([min_lon, min_lat], [max_lon, max_lat]);
        let mut out = Vec::new();
        for item in tree.locate_in_envelope_intersecting(&envelope) {
            if since.is_some_and(|value| item.node.updated_at <= value) { continue; }
            out.push(item.node.clone());
            if out.len() >= limit { break; }
        }
        out
    }
}
pub fn demo_mesh_nodes() -> Vec<MeshNode> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let ids = ["drone-a1", "drone-a2", "drone-a3", "drone-a4", "drone-a5", "drone-a6"];
    let base_lat = 37.7749; let base_lon = -122.4194;
    ids.iter().enumerate().map(|(idx, id)| MeshNode {
        id: id.to_string(), name: format!("Drone {}", idx + 1),
        lat: base_lat + (idx as f64) * 0.0017, lon: base_lon + (idx as f64) * 0.0012,
        alt: Some(110.0 + idx as f64 * 6.0), heading: Some((idx as f64 * 32.0) % 360.0),
        rssi_dbm: Some(-64 - idx as i32), latency_ms: Some(12 + idx as u32 * 5),
        status: "online".to_string(),
        neighbors: match idx {
            0 => vec![ids[1].to_string()], 1 => vec![ids[0].to_string(), ids[2].to_string()],
            2 => vec![ids[1].to_string(), ids[3].to_string()], 3 => vec![ids[2].to_string(), ids[4].to_string()],
            4 => vec![ids[3].to_string(), ids[5].to_string()], _ => vec![ids[4].to_string()],
        },
        stream_id: Some(format!("stream-{}", idx + 1)), updated_at: now,
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(lat: f64, lon: f64) -> MeshNode {
        MeshNode {
            id: "mesh-test".into(),
            name: "mesh test".into(),
            lat,
            lon,
            alt: None,
            heading: None,
            rssi_dbm: None,
            latency_ms: None,
            status: "online".into(),
            neighbors: Vec::new(),
            stream_id: None,
            updated_at: 1,
        }
    }

    #[test]
    fn rejects_non_finite_coordinates_without_mutating_store() {
        let store = MeshStore::new();
        store.upsert_node(node(f64::NAN, 1.0));
        store.upsert_node(node(1.0, f64::INFINITY));
        assert!(store.snapshot().nodes.is_empty());
    }

    #[test]
    fn accepts_finite_coordinates() {
        let store = MeshStore::new();
        store.upsert_node(node(37.0, -122.0));
        assert_eq!(store.snapshot().nodes.len(), 1);
    }
}
