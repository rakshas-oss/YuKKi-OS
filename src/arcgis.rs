//! ArcGIS-oriented avenue geometry using interoperable GeoJSON.
//!
//! This module intentionally uses RFC 7946 GeoJSON rather than an
//! ArcGIS-proprietary transport. Coordinates are WGS84 longitude/latitude in
//! that order; optional `route_id` and `avenue_name` properties preserve the
//! useful road-network metadata without assigning ArcGIS-specific semantics
//! to the legacy NXR1 numeric fields.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::broker_client::{BrokerClientError, BrokerTask};

/// Broker kind for the GeoJSON avenue feature representation.
pub const ARCGIS_AVENUE_KIND: &str = "geospatial.arcgis.avenue.v1";
/// JSON property key used by the broker adapter.
pub const ARCGIS_AVENUE_BROKER_KEY: &str = "arcgis_avenue";
/// Maximum serialized feature size.
pub const ARCGIS_AVENUE_MAX_BYTES: usize = 64 * 1024;
/// Maximum positions in one avenue LineString.
pub const ARCGIS_AVENUE_MAX_COORDINATES: usize = 10_000;
const MAX_METADATA_BYTES: usize = 256;

/// A WGS84 two-dimensional position in GeoJSON order: longitude, latitude.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Wgs84Coordinate {
    pub longitude: f64,
    pub latitude: f64,
}

/// A GeoJSON LineString feature representing an avenue or road-network route.
#[derive(Debug, Clone, PartialEq)]
pub struct ArcGisAvenue {
    /// GeoJSON feature identifier.
    pub feature_id: String,
    /// Optional route/network identifier retained as interoperable metadata.
    pub route_id: Option<String>,
    /// Optional avenue or road name.
    pub avenue_name: Option<String>,
    /// WGS84 positions in GeoJSON order (longitude, latitude).
    pub coordinates: Vec<Wgs84Coordinate>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GeoJsonFeature {
    #[serde(rename = "type")]
    feature_type: String,
    id: String,
    geometry: GeoJsonLineString,
    properties: AvenueProperties,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GeoJsonLineString {
    #[serde(rename = "type")]
    geometry_type: String,
    coordinates: Vec<[f64; 2]>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AvenueProperties {
    #[serde(skip_serializing_if = "Option::is_none")]
    route_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    avenue_name: Option<String>,
}

/// Errors produced by the ArcGIS/GeoJSON avenue codec.
#[derive(Debug, Error)]
pub enum ArcGisError {
    #[error("GeoJSON avenue feature is malformed: {0}")]
    Malformed(#[from] serde_json::Error),
    #[error("GeoJSON avenue feature is {size} bytes, exceeding max {max}")]
    TooLarge { size: usize, max: usize },
    #[error("avenue field '{field}' must contain between 1 and {max} bytes")]
    InvalidMetadata { field: &'static str, max: usize },
    #[error("avenue geometry requires at least two positions, got {found}")]
    TooFewCoordinates { found: usize },
    #[error("avenue geometry has {found} positions, exceeding max {max}")]
    TooManyCoordinates { found: usize, max: usize },
    #[error("coordinate {index} has invalid longitude {value}; expected [-180, 180]")]
    InvalidLongitude { index: usize, value: f64 },
    #[error("coordinate {index} has invalid latitude {value}; expected [-90, 90]")]
    InvalidLatitude { index: usize, value: f64 },
    #[error("GeoJSON feature type must be 'Feature', got '{0}'")]
    InvalidFeatureType(String),
    #[error("GeoJSON geometry type must be 'LineString', got '{0}'")]
    InvalidGeometryType(String),
    #[error("broker task kind '{found}' does not match expected '{expected}'")]
    UnexpectedKind { expected: String, found: String },
    #[error("broker task payload is missing the '{0}' field")]
    MissingBrokerPayload(&'static str),
}

impl PartialEq for ArcGisError {
    fn eq(&self, other: &Self) -> bool {
        use ArcGisError::*;
        match (self, other) {
            (Malformed(a), Malformed(b)) => a.to_string() == b.to_string(),
            (TooLarge { size: a, max: b }, TooLarge { size: c, max: d }) => a == c && b == d,
            (InvalidMetadata { field: a, max: b }, InvalidMetadata { field: c, max: d }) => {
                a == c && b == d
            }
            (TooFewCoordinates { found: a }, TooFewCoordinates { found: b }) => a == b,
            (TooManyCoordinates { found: a, max: b }, TooManyCoordinates { found: c, max: d }) => {
                a == c && b == d
            }
            (InvalidLongitude { index: a, value: b }, InvalidLongitude { index: c, value: d }) => {
                a == c && b == d
            }
            (InvalidLatitude { index: a, value: b }, InvalidLatitude { index: c, value: d }) => {
                a == c && b == d
            }
            (InvalidFeatureType(a), InvalidFeatureType(b)) => a == b,
            (InvalidGeometryType(a), InvalidGeometryType(b)) => a == b,
            (
                UnexpectedKind {
                    expected: a,
                    found: b,
                },
                UnexpectedKind {
                    expected: c,
                    found: d,
                },
            ) => a == c && b == d,
            (MissingBrokerPayload(a), MissingBrokerPayload(b)) => a == b,
            _ => false,
        }
    }
}

impl From<ArcGisError> for BrokerClientError {
    fn from(error: ArcGisError) -> Self {
        BrokerClientError::InvalidRequest(error.to_string())
    }
}

impl ArcGisAvenue {
    /// Encode an avenue as a GeoJSON Feature with a WGS84 LineString.
    pub fn encode(&self) -> Result<Vec<u8>, ArcGisError> {
        self.validate()?;
        let feature = GeoJsonFeature {
            feature_type: "Feature".to_string(),
            id: self.feature_id.clone(),
            geometry: GeoJsonLineString {
                geometry_type: "LineString".to_string(),
                coordinates: self
                    .coordinates
                    .iter()
                    .map(|coordinate| [coordinate.longitude, coordinate.latitude])
                    .collect(),
            },
            properties: AvenueProperties {
                route_id: self.route_id.clone(),
                avenue_name: self.avenue_name.clone(),
            },
        };
        let bytes = serde_json::to_vec(&feature)?;
        if bytes.len() > ARCGIS_AVENUE_MAX_BYTES {
            return Err(ArcGisError::TooLarge {
                size: bytes.len(),
                max: ARCGIS_AVENUE_MAX_BYTES,
            });
        }
        Ok(bytes)
    }

    /// Decode and validate an encoded GeoJSON avenue Feature.
    pub fn decode(bytes: &[u8]) -> Result<Self, ArcGisError> {
        if bytes.len() > ARCGIS_AVENUE_MAX_BYTES {
            return Err(ArcGisError::TooLarge {
                size: bytes.len(),
                max: ARCGIS_AVENUE_MAX_BYTES,
            });
        }
        let feature: GeoJsonFeature = serde_json::from_slice(bytes)?;
        if feature.feature_type != "Feature" {
            return Err(ArcGisError::InvalidFeatureType(feature.feature_type));
        }
        if feature.geometry.geometry_type != "LineString" {
            return Err(ArcGisError::InvalidGeometryType(
                feature.geometry.geometry_type,
            ));
        }
        let avenue = Self {
            feature_id: feature.id,
            route_id: feature.properties.route_id,
            avenue_name: feature.properties.avenue_name,
            coordinates: feature
                .geometry
                .coordinates
                .into_iter()
                .map(|[longitude, latitude]| Wgs84Coordinate {
                    longitude,
                    latitude,
                })
                .collect(),
        };
        avenue.validate()?;
        Ok(avenue)
    }

    /// Validate identifiers and WGS84 coordinate ranges.
    pub fn validate(&self) -> Result<(), ArcGisError> {
        validate_metadata("feature_id", &self.feature_id)?;
        if let Some(route_id) = &self.route_id {
            validate_metadata("route_id", route_id)?;
        }
        if let Some(avenue_name) = &self.avenue_name {
            validate_metadata("avenue_name", avenue_name)?;
        }
        if self.coordinates.len() < 2 {
            return Err(ArcGisError::TooFewCoordinates {
                found: self.coordinates.len(),
            });
        }
        if self.coordinates.len() > ARCGIS_AVENUE_MAX_COORDINATES {
            return Err(ArcGisError::TooManyCoordinates {
                found: self.coordinates.len(),
                max: ARCGIS_AVENUE_MAX_COORDINATES,
            });
        }
        for (index, coordinate) in self.coordinates.iter().enumerate() {
            if !coordinate.longitude.is_finite()
                || !(-180.0..=180.0).contains(&coordinate.longitude)
            {
                return Err(ArcGisError::InvalidLongitude {
                    index,
                    value: coordinate.longitude,
                });
            }
            if !coordinate.latitude.is_finite() || !(-90.0..=90.0).contains(&coordinate.latitude) {
                return Err(ArcGisError::InvalidLatitude {
                    index,
                    value: coordinate.latitude,
                });
            }
        }
        Ok(())
    }

    /// Wrap the interoperable GeoJSON Feature in the existing BrokerTask JSON boundary.
    pub fn to_broker_task(
        &self,
        task_id: impl Into<String>,
        source: impl Into<String>,
        destination: impl Into<String>,
        priority: u8,
        timeout_ms: u32,
    ) -> Result<BrokerTask, ArcGisError> {
        let bytes = self.encode()?;
        let feature: Value = serde_json::from_slice(&bytes)?;
        Ok(BrokerTask {
            task_id: task_id.into(),
            source: source.into(),
            destination: destination.into(),
            kind: ARCGIS_AVENUE_KIND.to_string(),
            priority,
            timeout_ms,
            payload: serde_json::json!({ ARCGIS_AVENUE_BROKER_KEY: feature }),
        })
    }

    /// Extract an avenue from a compatible broker task.
    pub fn from_broker_task(task: &BrokerTask) -> Result<Self, ArcGisError> {
        if task.kind != ARCGIS_AVENUE_KIND {
            return Err(ArcGisError::UnexpectedKind {
                expected: ARCGIS_AVENUE_KIND.to_string(),
                found: task.kind.clone(),
            });
        }
        let feature = task
            .payload
            .get(ARCGIS_AVENUE_BROKER_KEY)
            .ok_or(ArcGisError::MissingBrokerPayload(ARCGIS_AVENUE_BROKER_KEY))?;
        let bytes = serde_json::to_vec(feature)?;
        Self::decode(&bytes)
    }
}

fn validate_metadata(field: &'static str, value: &str) -> Result<(), ArcGisError> {
    if value.trim().is_empty() || value.len() > MAX_METADATA_BYTES {
        return Err(ArcGisError::InvalidMetadata {
            field,
            max: MAX_METADATA_BYTES,
        });
    }
    Ok(())
}
