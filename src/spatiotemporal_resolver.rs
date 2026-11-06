//! Spatiotemporal payload resolution and component dispatch.
//!
//! Routes decoded NXR1 broker tasks to bounded component queues by their
//! broker destination. Sequence checks are scoped per source and destination,
//! so independent producers do not suppress one another. The NXR1 wire format
//! and existing broker envelope remain unchanged.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use thiserror::Error;

use crate::broker_client::BrokerTask;
use crate::mpmc::{BoundedMpmc, SendError};
use crate::nxr1::{from_broker_task, Nxr1Error, Nxr1Frame};

/// Whether a route accepts repeated/out-of-order frame sequence identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequencePolicy {
    /// Deliver every valid frame; useful when sequence IDs are not monotonic.
    AllowAll,
    /// For each source, accept only sequence IDs greater than the last
    /// successfully enqueued ID.
    RejectNonIncreasing,
}

/// A decoded frame together with the broker metadata needed by a component.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedPayload {
    pub source: String,
    pub destination: String,
    pub numa_node: Option<u32>,
    pub frame: Nxr1Frame,
}

struct RouteState {
    last_sequence_by_source: HashMap<String, u64>,
}

struct Route {
    destination: String,
    numa_node: Option<u32>,
    sequence_policy: SequencePolicy,
    queue: BoundedMpmc<ResolvedPayload>,
    state: Mutex<RouteState>,
}

/// Receiver handle returned when a component destination is registered.
/// Clones share the same bounded MPMC queue.
#[derive(Clone)]
pub struct PayloadReceiver {
    queue: BoundedMpmc<ResolvedPayload>,
}

impl PayloadReceiver {
    pub fn recv(&self) -> Option<ResolvedPayload> {
        self.queue.recv()
    }

    pub fn try_recv(&self) -> Option<ResolvedPayload> {
        self.queue.try_recv()
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.queue.capacity()
    }

    pub fn close(&self) {
        self.queue.close();
    }
}

/// Routes spatiotemporal broker payloads to registered component queues.
#[derive(Default)]
pub struct SpatiotemporalPayloadResolver {
    routes: Mutex<HashMap<String, Arc<Route>>>,
}

#[derive(Debug, Error, PartialEq)]
pub enum ResolverError {
    #[error("destination '{0}' is already registered")]
    DuplicateDestination(String),
    #[error("no component route registered for destination '{0}'")]
    UnknownDestination(String),
    #[error("frame sequence {sequence} from '{source}' is not newer than {last}")]
    StaleSequence {
        source: String,
        sequence: u64,
        last: u64,
    },
    #[error("component queue for destination '{0}' is full")]
    QueueFull(String),
    #[error("component queue for destination '{0}' is closed")]
    QueueClosed(String),
    #[error(transparent)]
    InvalidFrame(#[from] Nxr1Error),
}

impl SpatiotemporalPayloadResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a component destination and return its consumer handle.
    ///
    /// The NUMA node is an advisory placement hint. Thread pinning and memory
    /// placement remain the consuming scheduler's responsibility.
    pub fn register_destination(
        &self,
        destination: impl Into<String>,
        capacity: usize,
        numa_node: Option<u32>,
        sequence_policy: SequencePolicy,
    ) -> Result<PayloadReceiver, ResolverError> {
        let destination = destination.into();
        let queue = BoundedMpmc::new(capacity)
            .map_err(|_| ResolverError::QueueFull(destination.clone()))?;
        let route = Arc::new(Route {
            destination: destination.clone(),
            numa_node,
            sequence_policy,
            queue: queue.clone(),
            state: Mutex::new(RouteState {
                last_sequence_by_source: HashMap::new(),
            }),
        });

        let mut routes = self.routes.lock().unwrap_or_else(|p| p.into_inner());
        if routes.contains_key(&destination) {
            return Err(ResolverError::DuplicateDestination(destination));
        }
        routes.insert(destination, route);
        Ok(PayloadReceiver { queue })
    }

    /// Decode an NXR1 broker task and enqueue it on its destination route.
    ///
    /// Destination selects the component; source and sequence ID scope
    /// temporal ordering. Frame coordinates and dynamics are preserved for
    /// the consumer without being reinterpreted by the resolver.
    pub fn resolve_and_enqueue(&self, task: &BrokerTask) -> Result<u64, ResolverError> {
        let route = {
            let routes = self.routes.lock().unwrap_or_else(|p| p.into_inner());
            routes
                .get(&task.destination)
                .cloned()
                .ok_or_else(|| ResolverError::UnknownDestination(task.destination.clone()))?
        };

        let frame = from_broker_task(task)?;
        let sequence = frame.seq_id;
        let mut state = route.state.lock().unwrap_or_else(|p| p.into_inner());

        if route.sequence_policy == SequencePolicy::RejectNonIncreasing {
            if let Some(last) = state.last_sequence_by_source.get(&task.source).copied() {
                if sequence <= last {
                    return Err(ResolverError::StaleSequence {
                        source: task.source.clone(),
                        sequence,
                        last,
                    });
                }
            }
        }

        let payload = ResolvedPayload {
            source: task.source.clone(),
            destination: route.destination.clone(),
            numa_node: route.numa_node,
            frame,
        };

        match route.queue.try_send(payload) {
            Ok(()) => {
                if route.sequence_policy == SequencePolicy::RejectNonIncreasing {
                    state.last_sequence_by_source.insert(task.source.clone(), sequence);
                }
                Ok(sequence)
            }
            Err(SendError::Full(_)) => Err(ResolverError::QueueFull(route.destination.clone())),
            Err(SendError::Closed(_)) => {
                Err(ResolverError::QueueClosed(route.destination.clone()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ResolverError, SequencePolicy, SpatiotemporalPayloadResolver};
    use crate::nxr1::{to_broker_task, Nxr1Frame};

    fn task(source: &str, destination: &str, sequence: u64) -> crate::broker_client::BrokerTask {
        let frame = Nxr1Frame {
            seq_id: sequence,
            x: 1.0,
            y: 2.0,
            z: 3.0,
            u: 0.1,
            v: 0.2,
            w: 0.3,
            fluidity: 0.9,
            drag: 0.1,
            divergence: 0.0,
            payload: vec![1, 2, 3],
        };
        to_broker_task(&frame, format!("task-{sequence}"), source, destination, 1, 1000)
            .unwrap()
    }

    #[test]
    fn resolves_payload_to_registered_component_and_preserves_frame() {
        let resolver = SpatiotemporalPayloadResolver::new();
        let receiver = resolver
            .register_destination("physics", 4, Some(1), SequencePolicy::AllowAll)
            .unwrap();

        assert_eq!(resolver.resolve_and_enqueue(&task("sensor-a", "physics", 7)), Ok(7));
        let resolved = receiver.try_recv().unwrap();
        assert_eq!(resolved.source, "sensor-a");
        assert_eq!(resolved.destination, "physics");
        assert_eq!(resolved.numa_node, Some(1));
        assert_eq!(resolved.frame.seq_id, 7);
        assert_eq!(resolved.frame.payload, vec![1, 2, 3]);
        assert_eq!(resolved.frame.x, 1.0);
    }

    #[test]
    fn temporal_ordering_is_per_source_and_commits_only_after_enqueue() {
        let resolver = SpatiotemporalPayloadResolver::new();
        let receiver = resolver
            .register_destination("scheduler", 2, None, SequencePolicy::RejectNonIncreasing)
            .unwrap();

        assert_eq!(resolver.resolve_and_enqueue(&task("a", "scheduler", 10)), Ok(10));
        assert_eq!(resolver.resolve_and_enqueue(&task("b", "scheduler", 3)), Ok(3));
        assert!(matches!(
            resolver.resolve_and_enqueue(&task("a", "scheduler", 10)),
            Err(ResolverError::StaleSequence { .. })
        ));
        assert_eq!(receiver.try_recv().unwrap().source, "a");
        assert_eq!(receiver.try_recv().unwrap().source, "b");
    }

    #[test]
    fn full_queue_does_not_advance_sequence_watermark() {
        let resolver = SpatiotemporalPayloadResolver::new();
        let receiver = resolver
            .register_destination("gpu", 1, None, SequencePolicy::RejectNonIncreasing)
            .unwrap();

        assert_eq!(resolver.resolve_and_enqueue(&task("a", "gpu", 1)), Ok(1));
        assert!(matches!(
            resolver.resolve_and_enqueue(&task("a", "gpu", 2)),
            Err(ResolverError::QueueFull(_))
        ));
        assert_eq!(receiver.try_recv().unwrap().frame.seq_id, 1);
        assert_eq!(resolver.resolve_and_enqueue(&task("a", "gpu", 2)), Ok(2));
    }

    #[test]
    fn unknown_and_duplicate_destinations_are_rejected() {
        let resolver = SpatiotemporalPayloadResolver::new();
        assert!(matches!(
            resolver.resolve_and_enqueue(&task("a", "missing", 1)),
            Err(ResolverError::UnknownDestination(_))
        ));
        resolver
            .register_destination("worker", 1, None, SequencePolicy::AllowAll)
            .unwrap();
        assert!(matches!(
            resolver.register_destination("worker", 1, None, SequencePolicy::AllowAll),
            Err(ResolverError::DuplicateDestination(_))
        ));
    }
}
