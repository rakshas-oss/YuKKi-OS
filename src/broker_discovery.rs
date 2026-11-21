//! Bounded lease-based discovery records for Overhauled broker services.
//!
//! Records are exchanged only inside YuKKi-OS's authenticated peer channel.
//! This registry is a control-plane cache, not an execution authorization
//! mechanism. Callers must still enforce the deployment's broker transport
//! security boundary before submitting work.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

pub const BROKER_SERVICE_KIND: &str = "overhauled.worker-broker";
pub const BROKER_SERVICE_SCHEMA: u16 = 1;
pub const BROKER_SERVICE_MAX_ENDPOINT_BYTES: usize = 256;
pub const BROKER_SERVICE_MAX_CAPABILITIES: usize = 16;
pub const BROKER_SERVICE_MAX_PROTOCOLS: usize = 4;
pub const BROKER_SERVICE_MAX_LEASE_SECS: u64 = 300;
pub const BROKER_SERVICE_MAX_RECORDS: usize = 4096;
pub const BROKER_SERVICE_MAX_HOPS: u8 = 8;
pub const BROKER_SERVICE_DEFAULT_LEASE_SECS: u64 = 90;
pub const BROKER_SERVICE_MAX_FRAME_BYTES: u32 = 16 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BrokerServiceRecord {
    pub schema: u16,
    pub service_id: Uuid,
    pub node_id: Uuid,
    pub service_kind: String,
    pub endpoint: String,
    pub protocol_versions: Vec<String>,
    pub capabilities: Vec<String>,
    pub max_frame_bytes: u32,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub message_id: Uuid,
    pub remaining_hops: u8,
}

impl BrokerServiceRecord {
    pub fn validate(&self, now_unix: u64) -> Result<(), BrokerDiscoveryError> {
        if self.schema != BROKER_SERVICE_SCHEMA {
            return Err(BrokerDiscoveryError::Invalid("unsupported service-record schema"));
        }
        if self.service_kind != BROKER_SERVICE_KIND {
            return Err(BrokerDiscoveryError::Invalid("unexpected service kind"));
        }
        if self.endpoint.is_empty()
            || self.endpoint.len() > BROKER_SERVICE_MAX_ENDPOINT_BYTES
            || self.endpoint.trim() != self.endpoint
            || self.endpoint.chars().any(char::is_whitespace)
            || !self.endpoint.rsplit_once(':').is_some_and(|(host, port)| {
                !host.is_empty()
                    && port.parse::<u16>().is_ok_and(|value| value != 0)
            })
        {
            return Err(BrokerDiscoveryError::Invalid("endpoint must be host:port or socket-address form"));
        }
        if self.protocol_versions.is_empty()
            || self.protocol_versions.len() > BROKER_SERVICE_MAX_PROTOCOLS
            || self.protocol_versions.iter().any(|v| {
                v.is_empty() || v.len() > 16 || !v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.')
            })
        {
            return Err(BrokerDiscoveryError::Invalid("invalid protocol-version list"));
        }
        if self.capabilities.len() > BROKER_SERVICE_MAX_CAPABILITIES
            || self.capabilities.iter().any(|v| {
                v.is_empty() || v.len() > 32 || !v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            })
        {
            return Err(BrokerDiscoveryError::Invalid("invalid capability list"));
        }
        if self.max_frame_bytes == 0 || self.max_frame_bytes > BROKER_SERVICE_MAX_FRAME_BYTES {
            return Err(BrokerDiscoveryError::Invalid("invalid maximum frame size"));
        }
        if self.expires_at_unix <= self.issued_at_unix
            || self.expires_at_unix.saturating_sub(self.issued_at_unix) > BROKER_SERVICE_MAX_LEASE_SECS
            || self.issued_at_unix > now_unix.saturating_add(30)
            || self.expires_at_unix <= now_unix
        {
            return Err(BrokerDiscoveryError::Invalid("expired or out-of-range service lease"));
        }
        if self.remaining_hops > BROKER_SERVICE_MAX_HOPS {
            return Err(BrokerDiscoveryError::Invalid("remaining hop count exceeds limit"));
        }
        Ok(())
    }

    pub fn forwarded(&self) -> Option<Self> {
        if self.remaining_hops <= 1 {
            return None;
        }
        let mut forwarded = self.clone();
        forwarded.remaining_hops -= 1;
        Some(forwarded)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BrokerDiscoveryError {
    #[error("invalid broker service record: {0}")]
    Invalid(&'static str),
    #[error("broker service registry is at capacity")]
    Capacity,
}

#[derive(Clone, Debug, Default)]
pub struct BrokerServiceRegistry {
    records: HashMap<Uuid, BrokerServiceRecord>,
}

impl BrokerServiceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn upsert(&mut self, record: BrokerServiceRecord, now_unix: u64) -> Result<(), BrokerDiscoveryError> {
        record.validate(now_unix)?;
        self.expire(now_unix);
        if !self.records.contains_key(&record.service_id)
            && self.records.len() >= BROKER_SERVICE_MAX_RECORDS
        {
            return Err(BrokerDiscoveryError::Capacity);
        }
        let replace = self.records.get(&record.service_id).is_none_or(|current| {
            current.node_id == record.node_id && record.issued_at_unix >= current.issued_at_unix
        });
        if replace {
            self.records.insert(record.service_id, record);
        }
        Ok(())
    }

    pub fn expire(&mut self, now_unix: u64) -> usize {
        let before = self.records.len();
        self.records.retain(|_, record| record.expires_at_unix > now_unix);
        before - self.records.len()
    }

    pub fn get(&mut self, service_id: Uuid, now_unix: u64) -> Option<&BrokerServiceRecord> {
        self.expire(now_unix);
        self.records.get(&service_id)
    }

    pub fn list(&mut self, now_unix: u64) -> Vec<BrokerServiceRecord> {
        self.expire(now_unix);
        let mut records: Vec<_> = self.records.values().cloned().collect();
        records.sort_by_key(|record| record.service_id);
        records
    }

    pub fn len(&mut self, now_unix: u64) -> usize {
        self.expire(now_unix);
        self.records.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(now: u64) -> BrokerServiceRecord {
        BrokerServiceRecord {
            schema: BROKER_SERVICE_SCHEMA,
            service_id: Uuid::new_v4(),
            node_id: Uuid::new_v4(),
            service_kind: BROKER_SERVICE_KIND.into(),
            endpoint: "127.0.0.1:9090".into(),
            protocol_versions: vec!["BRK1".into(), "BRK2".into()],
            capabilities: vec!["cpu".into(), "gpu".into(), "npu".into()],
            max_frame_bytes: 64 * 1024,
            issued_at_unix: now,
            expires_at_unix: now + BROKER_SERVICE_DEFAULT_LEASE_SECS,
            message_id: Uuid::new_v4(),
            remaining_hops: BROKER_SERVICE_MAX_HOPS,
        }
    }

    #[test]
    fn accepts_valid_record_and_expires_lease() {
        let mut registry = BrokerServiceRegistry::new();
        let value = record(100);
        let id = value.service_id;
        registry.upsert(value, 100).unwrap();
        assert!(registry.get(id, 189).is_some());
        assert!(registry.get(id, 190).is_none());
        assert_eq!(registry.len(190), 0);
    }

    #[test]
    fn rejects_expired_or_overlong_leases() {
        let mut expired = record(100);
        expired.expires_at_unix = 100;
        assert!(expired.validate(100).is_err());
        let mut long = record(100);
        long.expires_at_unix = 100 + BROKER_SERVICE_MAX_LEASE_SECS + 1;
        assert!(long.validate(100).is_err());
    }

    #[test]
    fn rejects_invalid_endpoint_and_frame_bound() {
        let mut invalid = record(100);
        invalid.endpoint = "http://broker:9090/path".into();
        assert!(invalid.validate(100).is_err());
        let mut oversized = record(100);
        oversized.max_frame_bytes = BROKER_SERVICE_MAX_FRAME_BYTES + 1;
        assert!(oversized.validate(100).is_err());
    }

    #[test]
    fn forwarding_decrements_hops_and_stops_at_one() {
        let mut value = record(100);
        value.remaining_hops = 2;
        let forwarded = value.forwarded().unwrap();
        assert_eq!(forwarded.remaining_hops, 1);
        assert!(forwarded.forwarded().is_none());
    }

    #[test]
    fn registry_capacity_is_bounded() {
        assert_eq!(BROKER_SERVICE_MAX_RECORDS, 4096);
        assert_eq!(BROKER_SERVICE_MAX_HOPS, 8);
    }
}
