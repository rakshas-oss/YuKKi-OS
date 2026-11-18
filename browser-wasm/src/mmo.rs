//! Portable MMO spatial and motion primitives for the browser WASM runtime.
//!
//! This module deliberately contains no POSIX, pthread, futex, shared-memory,
//! SIMD-intrinsic, or native-device dependencies. Browser scheduling and I/O
//! remain in the host page; this module provides bounded deterministic state
//! and math that can also be unit-tested on native targets.

pub const MAX_ENTITIES: usize = 512;
pub const WGS84_A: f64 = 6_378_137.0;
pub const WGS84_E2: f64 = 0.006_694_379_990_14;
const DEG_TO_RAD: f64 = core::f64::consts::PI / 180.0;
const TWO_PI: f64 = core::f64::consts::PI * 2.0;

pub const OK: i32 = 0;
pub const ERR_INVALID: i32 = -1;
pub const ERR_FULL: i32 = -2;
pub const ERR_NOT_FOUND: i32 = -3;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Wgs84 {
    pub lat_deg: f64,
    pub lon_deg: f64,
    pub alt_m: f64,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Vec3 {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

#[derive(Clone, Copy, Debug)]
struct GeoAnchor {
    ecef: Vec3,
    sin_lat: f64,
    cos_lat: f64,
    sin_lon: f64,
    cos_lon: f64,
}

#[derive(Clone, Copy, Debug)]
struct Entity {
    used: bool,
    id: u32,
    position: Wgs84,
    ecef: Vec3,
    timestamp_ns: u64,
    radius_m: f64,
}

impl Entity {
    const EMPTY: Self = Self {
        used: false,
        id: 0,
        position: Wgs84 { lat_deg: 0.0, lon_deg: 0.0, alt_m: 0.0 },
        ecef: Vec3 { x: 0.0, y: 0.0, z: 0.0 },
        timestamp_ns: 0,
        radius_m: 0.0,
    };
}

#[derive(Clone)]
pub struct SpatialState {
    entities: [Entity; MAX_ENTITIES],
    len: usize,
    query_indices: [u16; MAX_ENTITIES],
    query_len: usize,
}

impl SpatialState {
    pub const fn new() -> Self {
        Self {
            entities: [Entity::EMPTY; MAX_ENTITIES],
            len: 0,
            query_indices: [0; MAX_ENTITIES],
            query_len: 0,
        }
    }

    pub fn reset(&mut self) {
        self.entities = [Entity::EMPTY; MAX_ENTITIES];
        self.len = 0;
        self.query_len = 0;
    }

    pub fn len(&self) -> usize { self.len }
    pub fn is_empty(&self) -> bool { self.len == 0 }

    /// Insert or replace a stable entity ID. Returns its zero-based slot.
    pub fn upsert(
        &mut self,
        id: u32,
        position: Wgs84,
        timestamp_ns: u64,
        radius_m: f64,
    ) -> Result<usize, i32> {
        if !valid_wgs84(position) || !radius_m.is_finite() || radius_m < 0.0 {
            return Err(ERR_INVALID);
        }
        let ecef = wgs84_to_ecef(position);
        let slot = match self.entities[..self.len].iter().position(|entity| entity.id == id) {
            Some(index) => index,
            None if self.len < MAX_ENTITIES => {
                let index = self.len;
                self.len += 1;
                index
            }
            None => return Err(ERR_FULL),
        };
        self.entities[slot] = Entity {
            used: true,
            id,
            position,
            ecef,
            timestamp_ns,
            radius_m,
        };
        Ok(slot)
    }

    /// Query an inclusive WGS84 rectangle. west > east crosses the antimeridian.
    pub fn query_wgs84_bbox(
        &mut self,
        south: f64,
        west: f64,
        north: f64,
        east: f64,
    ) -> Result<usize, i32> {
        if !south.is_finite()
            || !north.is_finite()
            || !west.is_finite()
            || !east.is_finite()
            || south < -90.0
            || north > 90.0
            || south > north
            || west < -180.0
            || west > 180.0
            || east < -180.0
            || east > 180.0
        {
            return Err(ERR_INVALID);
        }

        self.query_len = 0;
        for index in 0..self.len {
            let entity = self.entities[index];
            if !entity.used { continue; }
            let lon_matches = if west <= east {
                entity.position.lon_deg >= west && entity.position.lon_deg <= east
            } else {
                entity.position.lon_deg >= west || entity.position.lon_deg <= east
            };
            if entity.position.lat_deg >= south
                && entity.position.lat_deg <= north
                && lon_matches
            {
                self.query_indices[self.query_len] = index as u16;
                self.query_len += 1;
            }
        }
        Ok(self.query_len)
    }

    pub fn query_index(&self, result_index: usize) -> Option<usize> {
        if result_index >= self.query_len { None }
        else { Some(self.query_indices[result_index] as usize) }
    }

    pub fn entity(&self, index: usize) -> Option<(u32, Wgs84, Vec3, u64, f64)> {
        if index >= self.len { return None; }
        let entity = self.entities[index];
        if !entity.used { return None; }
        Some((entity.id, entity.position, entity.ecef, entity.timestamp_ns, entity.radius_m))
    }

    /// Resolve the nearest observation not newer than at_ns and no older than max_age_ns.
    pub fn resolve_nearest(
        &self,
        query: Wgs84,
        at_ns: u64,
        max_age_ns: u64,
        max_distance_m: f64,
    ) -> Result<Option<usize>, i32> {
        if !valid_wgs84(query) || !max_distance_m.is_finite() || max_distance_m < 0.0 {
            return Err(ERR_INVALID);
        }
        let target = wgs84_to_ecef(query);
        let max_distance_sq = max_distance_m * max_distance_m;
        let mut best: Option<usize> = None;
        let mut best_distance_sq = max_distance_sq;

        for index in 0..self.len {
            let entity = self.entities[index];
            if !entity.used || entity.timestamp_ns > at_ns { continue; }
            if at_ns - entity.timestamp_ns > max_age_ns { continue; }
            let distance_sq = distance_squared(target, entity.ecef);
            if distance_sq < best_distance_sq
                || (distance_sq == best_distance_sq
                    && best.is_some_and(|current| entity.timestamp_ns > self.entities[current].timestamp_ns))
            {
                best = Some(index);
                best_distance_sq = distance_sq;
            }
        }
        Ok(best)
    }
}

fn valid_wgs84(position: Wgs84) -> bool {
    position.lat_deg.is_finite()
        && position.lon_deg.is_finite()
        && position.alt_m.is_finite()
        && (-90.0..=90.0).contains(&position.lat_deg)
        && (-180.0..=180.0).contains(&position.lon_deg)
}

fn distance_squared(a: Vec3, b: Vec3) -> f64 {
    let dx = a.x - b.x;
    let dy = a.y - b.y;
    let dz = a.z - b.z;
    dx * dx + dy * dy + dz * dz
}

// Small no_std math helpers. Range reduction keeps the Taylor polynomials
// accurate for every valid WGS84 latitude/longitude.
fn sin_cos(mut angle: f64) -> (f64, f64) {
    let pi = core::f64::consts::PI;
    while angle > pi { angle -= TWO_PI; }
    while angle < -pi { angle += TWO_PI; }

    let mut cos_sign = 1.0;
    if angle > pi * 0.5 {
        angle = pi - angle;
        cos_sign = -1.0;
    } else if angle < -pi * 0.5 {
        angle = -pi - angle;
        cos_sign = -1.0;
    }

    let x2 = angle * angle;
    let sin_poly = 1.0 + x2 * (-1.0 / 6.0 + x2 * (1.0 / 120.0
        + x2 * (-1.0 / 5040.0 + x2 * (1.0 / 362880.0
        + x2 * (-1.0 / 39916800.0 + x2 * (1.0 / 6227020800.0
        + x2 * (-1.0 / 1307674368000.0 + x2 * (1.0 / 355687428096000.0)))))));
    let cos_poly = 1.0 + x2 * (-1.0 / 2.0 + x2 * (1.0 / 24.0
        + x2 * (-1.0 / 720.0 + x2 * (1.0 / 40320.0
        + x2 * (-1.0 / 3628800.0 + x2 * (1.0 / 479001600.0
        + x2 * (-1.0 / 87178291200.0 + x2 * (1.0 / 20922789888000.0)))))));
    (angle * sin_poly, cos_sign * cos_poly)
}

fn sqrt(value: f64) -> f64 {
    if value == 0.0 { return 0.0; }
    if value < 0.0 { return f64::NAN; }
    if !value.is_finite() { return value; }
    let mut guess = f64::from_bits((value.to_bits() >> 1) + 0x1ff8_0000_0000_0000);
    for _ in 0..8 { guess = 0.5 * (guess + value / guess); }
    guess
}

fn anchor(origin: Wgs84) -> GeoAnchor {
    let lat = origin.lat_deg * DEG_TO_RAD;
    let lon = origin.lon_deg * DEG_TO_RAD;
    let (sin_lat, cos_lat) = sin_cos(lat);
    let (sin_lon, cos_lon) = sin_cos(lon);
    GeoAnchor {
        ecef: wgs84_to_ecef(origin),
        sin_lat,
        cos_lat,
        sin_lon,
        cos_lon,
    }
}

/// WGS84 geodetic coordinates to Earth-Centred, Earth-Fixed metres.
pub fn wgs84_to_ecef(position: Wgs84) -> Vec3 {
    let lat = position.lat_deg * DEG_TO_RAD;
    let lon = position.lon_deg * DEG_TO_RAD;
    let (sin_lat, cos_lat) = sin_cos(lat);
    let (sin_lon, cos_lon) = sin_cos(lon);
    let n = WGS84_A / sqrt(1.0 - WGS84_E2 * sin_lat * sin_lat);
    Vec3 {
        x: (n + position.alt_m) * cos_lat * cos_lon,
        y: (n + position.alt_m) * cos_lat * sin_lon,
        z: (n * (1.0 - WGS84_E2) + position.alt_m) * sin_lat,
    }
}

/// Transform one WGS84 point into the local east/north/up frame of an origin.
pub fn wgs84_to_enu(origin: Wgs84, position: Wgs84) -> Result<Vec3, i32> {
    if !valid_wgs84(origin) || !valid_wgs84(position) { return Err(ERR_INVALID); }
    let a = anchor(origin);
    let p = wgs84_to_ecef(position);
    let dx = p.x - a.ecef.x;
    let dy = p.y - a.ecef.y;
    let dz = p.z - a.ecef.z;
    Ok(Vec3 {
        x: -a.sin_lon * dx + a.cos_lon * dy,
        y: -a.sin_lat * a.cos_lon * dx - a.sin_lat * a.sin_lon * dy + a.cos_lat * dz,
        z: a.cos_lat * a.cos_lon * dx + a.cos_lat * a.sin_lon * dy + a.sin_lat * dz,
    })
}

/// Transform local east/north/up metres into ECEF metres around an origin.
pub fn enu_to_ecef(origin: Wgs84, enu: Vec3) -> Result<Vec3, i32> {
    if !valid_wgs84(origin) || !enu.x.is_finite() || !enu.y.is_finite() || !enu.z.is_finite() {
        return Err(ERR_INVALID);
    }
    let a = anchor(origin);
    let dx = -a.sin_lon * enu.x - a.sin_lat * a.cos_lon * enu.y + a.cos_lat * a.cos_lon * enu.z;
    let dy = a.cos_lon * enu.x - a.sin_lat * a.sin_lon * enu.y + a.cos_lat * a.sin_lon * enu.z;
    let dz = a.cos_lat * enu.y + a.sin_lat * enu.z;
    Ok(Vec3 { x: a.ecef.x + dx, y: a.ecef.y + dy, z: a.ecef.z + dz })
}

/// Cubic Hermite position interpolation. t is normalized to [0, 1], dt is seconds.
pub fn hermite_position(p0: Vec3, v0: Vec3, p1: Vec3, v1: Vec3, t: f64, dt: f64) -> Result<Vec3, i32> {
    let values = [p0.x, p0.y, p0.z, v0.x, v0.y, v0.z,
        p1.x, p1.y, p1.z, v1.x, v1.y, v1.z, t, dt];
    if values.iter().any(|value| !value.is_finite()) || !(0.0..=1.0).contains(&t) || dt < 0.0 {
        return Err(ERR_INVALID);
    }
    let t2 = t * t;
    let t3 = t2 * t;
    let h00 = 2.0 * t3 - 3.0 * t2 + 1.0;
    let h10 = t3 - 2.0 * t2 + t;
    let h01 = -2.0 * t3 + 3.0 * t2;
    let h11 = t3 - t2;
    Ok(Vec3 {
        x: h00 * p0.x + h10 * (v0.x * dt) + h01 * p1.x + h11 * (v1.x * dt),
        y: h00 * p0.y + h10 * (v0.y * dt) + h01 * p1.y + h11 * (v1.y * dt),
        z: h00 * p0.z + h10 * (v0.z * dt) + h01 * p1.z + h11 * (v1.z * dt),
    })
}

#[cfg(target_arch = "wasm32")]
static mut STATE: SpatialState = SpatialState::new();
#[cfg(target_arch = "wasm32")]
static mut GEO_OUTPUT: [f64; 3] = [0.0; 3];

#[cfg(target_arch = "wasm32")]
unsafe fn state_mut() -> &'static mut SpatialState {
    // This browser build is single-threaded; calls are serialized by its event loop.
    &mut *core::ptr::addr_of_mut!(STATE)
}

#[cfg(target_arch = "wasm32")]
fn write_output(value: Result<Vec3, i32>) -> *const f64 {
    match value {
        Ok(v) => {
            let output = core::ptr::addr_of_mut!(GEO_OUTPUT);
            unsafe { *output = [v.x, v.y, v.z]; }
            output.cast::<f64>()
        }
        Err(_) => core::ptr::null(),
    }
}

#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn adi_mmo_reset() { unsafe { state_mut().reset(); } }

#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn adi_mmo_entity_count() -> u32 {
    unsafe { state_mut().len() as u32 }
}

#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn adi_mmo_upsert_entity(
    id: u32, lat_deg: f64, lon_deg: f64, alt_m: f64, timestamp_ns: u64, radius_m: f64,
) -> i32 {
    let position = Wgs84 { lat_deg, lon_deg, alt_m };
    match unsafe { state_mut().upsert(id, position, timestamp_ns, radius_m) } {
        Ok(_) => OK,
        Err(error) => error,
    }
}

#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn adi_mmo_query_wgs84_bbox(south: f64, west: f64, north: f64, east: f64) -> i32 {
    match unsafe { state_mut().query_wgs84_bbox(south, west, north, east) } {
        Ok(count) => count as i32,
        Err(error) => error,
    }
}

#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn adi_mmo_query_count() -> u32 {
    unsafe { state_mut().query_len as u32 }
}

#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn adi_mmo_query_entity_index(result_index: u32) -> u32 {
    unsafe { state_mut().query_index(result_index as usize).map(|v| v as u32).unwrap_or(u32::MAX) }
}

#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn adi_mmo_entity_id(index: u32) -> u32 {
    unsafe { state_mut().entity(index as usize).map(|v| v.0).unwrap_or(u32::MAX) }
}

#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn adi_mmo_entity_lat(index: u32) -> f64 {
    unsafe { state_mut().entity(index as usize).map(|v| v.1.lat_deg).unwrap_or(f64::NAN) }
}

#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn adi_mmo_entity_lon(index: u32) -> f64 {
    unsafe { state_mut().entity(index as usize).map(|v| v.1.lon_deg).unwrap_or(f64::NAN) }
}

#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn adi_mmo_entity_alt(index: u32) -> f64 {
    unsafe { state_mut().entity(index as usize).map(|v| v.1.alt_m).unwrap_or(f64::NAN) }
}

#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn adi_mmo_entity_timestamp_ns(index: u32) -> u64 {
    unsafe { state_mut().entity(index as usize).map(|v| v.3).unwrap_or(0) }
}

#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn adi_mmo_resolve_nearest(
    lat_deg: f64, lon_deg: f64, alt_m: f64, at_ns: u64, max_age_ns: u64, max_distance_m: f64,
) -> u32 {
    let query = Wgs84 { lat_deg, lon_deg, alt_m };
    unsafe {
        state_mut().resolve_nearest(query, at_ns, max_age_ns, max_distance_m)
            .ok().flatten().map(|index| index as u32).unwrap_or(u32::MAX)
    }
}

#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn adi_mmo_wgs84_to_ecef(lat_deg: f64, lon_deg: f64, alt_m: f64) -> *const f64 {
    let position = Wgs84 { lat_deg, lon_deg, alt_m };
    if !valid_wgs84(position) { return core::ptr::null(); }
    write_output(Ok(wgs84_to_ecef(position)))
}

#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn adi_mmo_wgs84_to_enu(
    origin_lat_deg: f64, origin_lon_deg: f64, origin_alt_m: f64,
    lat_deg: f64, lon_deg: f64, alt_m: f64,
) -> *const f64 {
    write_output(wgs84_to_enu(
        Wgs84 { lat_deg: origin_lat_deg, lon_deg: origin_lon_deg, alt_m: origin_alt_m },
        Wgs84 { lat_deg, lon_deg, alt_m },
    ))
}

#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn adi_mmo_enu_to_ecef(
    origin_lat_deg: f64, origin_lon_deg: f64, origin_alt_m: f64,
    east_m: f64, north_m: f64, up_m: f64,
) -> *const f64 {
    write_output(enu_to_ecef(
        Wgs84 { lat_deg: origin_lat_deg, lon_deg: origin_lon_deg, alt_m: origin_alt_m },
        Vec3 { x: east_m, y: north_m, z: up_m },
    ))
}

#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn adi_mmo_hermite_position(
    p0x: f64, p0y: f64, p0z: f64,
    v0x: f64, v0y: f64, v0z: f64,
    p1x: f64, p1y: f64, p1z: f64,
    v1x: f64, v1y: f64, v1z: f64,
    t: f64, dt: f64,
) -> *const f64 {
    write_output(hermite_position(
        Vec3 { x: p0x, y: p0y, z: p0z },
        Vec3 { x: v0x, y: v0y, z: v0z },
        Vec3 { x: p1x, y: p1y, z: p1z },
        Vec3 { x: v1x, y: v1y, z: v1z },
        t, dt,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wgs84_origin_maps_to_equatorial_ecef() {
        let ecef = wgs84_to_ecef(Wgs84 { lat_deg: 0.0, lon_deg: 0.0, alt_m: 0.0 });
        assert!((ecef.x - WGS84_A).abs() < 0.01);
        assert!(ecef.y.abs() < 0.01);
        assert!(ecef.z.abs() < 0.01);
    }

    #[test]
    fn enu_has_real_up_component_and_round_trips_to_ecef() {
        let origin = Wgs84 { lat_deg: 43.6532, lon_deg: -79.3832, alt_m: 100.0 };
        let target = Wgs84 { lat_deg: 43.6542, lon_deg: -79.3822, alt_m: 125.0 };
        let enu = wgs84_to_enu(origin, target).unwrap();
        assert!(enu.x > 0.0 && enu.y > 0.0 && enu.z > 20.0);
        let reconstructed = enu_to_ecef(origin, enu).unwrap();
        let expected = wgs84_to_ecef(target);
        assert!(distance_squared(reconstructed, expected) < 0.01);
    }

    #[test]
    fn hermite_interpolation_preserves_endpoints() {
        let p0 = Vec3 { x: 1.0, y: 2.0, z: 3.0 };
        let p1 = Vec3 { x: 9.0, y: 8.0, z: 7.0 };
        let zero = Vec3 { x: 0.0, y: 0.0, z: 0.0 };
        assert_eq!(hermite_position(p0, zero, p1, zero, 0.0, 1.0).unwrap(), p0);
        assert_eq!(hermite_position(p0, zero, p1, zero, 1.0, 1.0).unwrap(), p1);
    }

    #[test]
    fn spatiotemporal_resolver_filters_future_and_stale_entities() {
        let mut state = SpatialState::new();
        state.upsert(1, Wgs84 { lat_deg: 43.6532, lon_deg: -79.3832, alt_m: 100.0 }, 90, 2.0).unwrap();
        state.upsert(2, Wgs84 { lat_deg: 43.6533, lon_deg: -79.3832, alt_m: 100.0 }, 110, 2.0).unwrap();
        state.upsert(3, Wgs84 { lat_deg: 43.65321, lon_deg: -79.3832, alt_m: 100.0 }, 10, 2.0).unwrap();
        let resolved = state.resolve_nearest(
            Wgs84 { lat_deg: 43.6532, lon_deg: -79.3832, alt_m: 100.0 },
            100, 20, 100.0,
        ).unwrap();
        assert_eq!(resolved, Some(0));
    }

    #[test]
    fn bbox_query_handles_antimeridian() {
        let mut state = SpatialState::new();
        state.upsert(1, Wgs84 { lat_deg: 10.0, lon_deg: 179.5, alt_m: 0.0 }, 1, 0.0).unwrap();
        state.upsert(2, Wgs84 { lat_deg: 10.0, lon_deg: -179.5, alt_m: 0.0 }, 1, 0.0).unwrap();
        state.upsert(3, Wgs84 { lat_deg: 10.0, lon_deg: 0.0, alt_m: 0.0 }, 1, 0.0).unwrap();
        assert_eq!(state.query_wgs84_bbox(9.0, 170.0, 11.0, -170.0).unwrap(), 2);
    }

    #[test]
    fn rejects_invalid_coordinates_and_bounds_capacity() {
        let mut state = SpatialState::new();
        assert_eq!(
            state.upsert(1, Wgs84 { lat_deg: 91.0, lon_deg: 0.0, alt_m: 0.0 }, 1, 0.0),
            Err(ERR_INVALID)
        );
        for id in 0..MAX_ENTITIES as u32 {
            state.upsert(id, Wgs84 { lat_deg: 0.0, lon_deg: 0.0, alt_m: 0.0 }, id as u64, 0.0).unwrap();
        }
        assert_eq!(
            state.upsert(9999, Wgs84 { lat_deg: 0.0, lon_deg: 0.0, alt_m: 0.0 }, 0, 0.0),
            Err(ERR_FULL)
        );
    }
}
