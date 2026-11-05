use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

struct State<T> {
    items: VecDeque<T>,
    closed: bool,
}
struct Shared<T> {
    capacity: usize,
    state: Mutex<State<T>>,
    not_empty: Condvar,
    not_full: Condvar,
}

/// Cloneable bounded multi-producer/multi-consumer queue.
/// Uses a mutex/condition variables for auditable blocking semantics.
pub struct BoundedMpmc<T> {
    shared: Arc<Shared<T>>,
}

impl<T> Clone for BoundedMpmc<T> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SendError<T> {
    Full(T),
    Closed(T),
}

impl<T> BoundedMpmc<T> {
    pub fn new(capacity: usize) -> Result<Self, &'static str> {
        if capacity == 0 {
            return Err("MPMC queue capacity must be greater than zero");
        }
        Ok(Self {
            shared: Arc::new(Shared {
                capacity,
                state: Mutex::new(State {
                    items: VecDeque::with_capacity(capacity),
                    closed: false,
                }),
                not_empty: Condvar::new(),
                not_full: Condvar::new(),
            }),
        })
    }

    fn lock(&self) -> MutexGuard<'_, State<T>> {
        self.shared.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn try_send(&self, item: T) -> Result<(), SendError<T>> {
        let mut state = self.lock();
        if state.closed {
            return Err(SendError::Closed(item));
        }
        if state.items.len() == self.shared.capacity {
            return Err(SendError::Full(item));
        }
        state.items.push_back(item);
        self.shared.not_empty.notify_one();
        Ok(())
    }

    pub fn send(&self, item: T) -> Result<(), SendError<T>> {
        let mut state = self.lock();
        let mut item = Some(item);
        loop {
            if state.closed {
                return Err(SendError::Closed(item.take().unwrap()));
            }
            if state.items.len() < self.shared.capacity {
                state.items.push_back(item.take().unwrap());
                self.shared.not_empty.notify_one();
                return Ok(());
            }
            state = self
                .shared
                .not_full
                .wait(state)
                .unwrap_or_else(|p| p.into_inner());
        }
    }

    pub fn try_recv(&self) -> Option<T> {
        let mut state = self.lock();
        let item = state.items.pop_front();
        if item.is_some() {
            self.shared.not_full.notify_one();
        }
        item
    }

    pub fn recv(&self) -> Option<T> {
        let mut state = self.lock();
        loop {
            if let Some(item) = state.items.pop_front() {
                self.shared.not_full.notify_one();
                return Some(item);
            }
            if state.closed {
                return None;
            }
            state = self
                .shared
                .not_empty
                .wait(state)
                .unwrap_or_else(|p| p.into_inner());
        }
    }

    /// Close the queue, wake all waiters, reject new sends, and drain queued items.
    pub fn close(&self) {
        let mut state = self.lock();
        state.closed = true;
        self.shared.not_empty.notify_all();
        self.shared.not_full.notify_all();
    }

    pub fn is_closed(&self) -> bool {
        self.lock().closed
    }
    pub fn len(&self) -> usize {
        self.lock().items.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn capacity(&self) -> usize {
        self.shared.capacity
    }
}

#[cfg(test)]
mod tests {
    use super::{BoundedMpmc, SendError};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use std::thread;

    #[test]
    fn bounded_and_close_semantics() {
        let q = BoundedMpmc::new(1).unwrap();
        q.try_send(1).unwrap();
        assert_eq!(q.try_send(2), Err(SendError::Full(2)));
        assert_eq!(q.try_recv(), Some(1));
        q.send(7).unwrap();
        q.close();
        assert_eq!(q.try_send(8), Err(SendError::Closed(8)));
        assert_eq!(q.recv(), Some(7));
        assert_eq!(q.recv(), None);
    }

    #[test]
    fn rejects_zero_capacity() {
        assert!(BoundedMpmc::<u8>::new(0).is_err());
    }

    #[test]
    fn mpmc_delivers_every_item_once() {
        const P: usize = 4;
        const C: usize = 4;
        const N: usize = 1500;
        let q: BoundedMpmc<usize> = BoundedMpmc::new(29).unwrap();
        let total = Arc::new(AtomicUsize::new(0));
        let seen = Arc::new(std::sync::Mutex::new(vec![false; P * N]));
        let mut consumers = Vec::new();
        for _ in 0..C {
            let q = q.clone();
            let total = Arc::clone(&total);
            let seen = Arc::clone(&seen);
            consumers.push(thread::spawn(move || {
                while let Some(item) = q.recv() {
                    let mut seen = seen.lock().unwrap();
                    assert!(item < seen.len());
                    assert!(!seen[item], "duplicate queue item: {item}");
                    seen[item] = true;
                    total.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }
        let mut producers = Vec::new();
        for p in 0..P {
            let q = q.clone();
            producers.push(thread::spawn(move || {
                for n in 0..N {
                    q.send(p * N + n).unwrap();
                }
            }));
        }
        for p in producers {
            p.join().unwrap();
        }
        q.close();
        for c in consumers {
            c.join().unwrap();
        }
        assert_eq!(total.load(Ordering::Relaxed), P * N);
        assert!(seen.lock().unwrap().iter().all(|item| *item));
    }

    #[test]
    fn close_wakes_waiting_receiver() {
        let q = BoundedMpmc::<u8>::new(1).unwrap();
        let worker_q = q.clone();
        let worker = thread::spawn(move || worker_q.recv());
        q.close();
        assert_eq!(worker.join().unwrap(), None);
    }
}
