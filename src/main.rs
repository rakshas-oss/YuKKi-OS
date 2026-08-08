use std::env;
use std::ptr;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SpatiotemporalFrame {
    seq_id: u64,
    x: f64,
    y: f64,
    z: f64,
    u: f64,
    v: f64,
    w: f64,
    fluidity: f32,
    drag: f32,
    divergence: f64,
    payload: [u8; 16],
}

#[link(name = "chaos_weave")]
unsafe extern "C" {
    fn chaos_engine_init(sigma: f64, rho: f64, beta: f64);
    fn chaos_engine_init_with_state(sigma: f64, rho: f64, beta: f64, x0: f64, y0: f64, z0: f64);
    fn weave_spatiotemporal_frame(seq: u64, payload_src: *const u8, out_frame: *mut SpatiotemporalFrame);
}

#[derive(Debug, Clone, Copy)]
struct LorenzConfig {
    sigma: f64,
    rho: f64,
    beta: f64,
    x0: f64,
    y0: f64,
    z0: f64,
}

impl Default for LorenzConfig {
    fn default() -> Self {
        Self {
            sigma: 10.0,
            rho: 28.0,
            beta: 8.33333333333,
            x0: 0.1,
            y0: 0.0,
            z0: 0.0,
        }
    }
}

impl LorenzConfig {
    fn from_env() -> Self {
        let default = Self::default();
        Self {
            sigma: parse_env_f64("YUKKI_LORENZ_SIGMA", default.sigma),
            rho: parse_env_f64("YUKKI_LORENZ_RHO", default.rho),
            beta: parse_env_f64("YUKKI_LORENZ_BETA", default.beta),
            x0: parse_env_f64("YUKKI_LORENZ_X0", default.x0),
            y0: parse_env_f64("YUKKI_LORENZ_Y0", default.y0),
            z0: parse_env_f64("YUKKI_LORENZ_Z0", default.z0),
        }
    }
}

fn parse_env_f64(key: &str, fallback: f64) -> f64 {
    match env::var(key) {
        Ok(value) => value.parse::<f64>().unwrap_or(fallback),
        Err(_) => fallback,
    }
}

fn main() {
    let config = LorenzConfig::from_env();
    let defaults = LorenzConfig::default();
    unsafe {
        if config.x0 == defaults.x0 && config.y0 == defaults.y0 && config.z0 == defaults.z0 {
            chaos_engine_init(config.sigma, config.rho, config.beta);
        } else {
            chaos_engine_init_with_state(
                config.sigma,
                config.rho,
                config.beta,
                config.x0,
                config.y0,
                config.z0,
            );
        }
    }

    let mut frame = SpatiotemporalFrame {
        seq_id: 0,
        x: 0.0,
        y: 0.0,
        z: 0.0,
        u: 0.0,
        v: 0.0,
        w: 0.0,
        fluidity: 0.0,
        drag: 0.0,
        divergence: 0.0,
        payload: [0; 16],
    };
    unsafe { weave_spatiotemporal_frame(0, ptr::null(), &mut frame) };
    println!(
        "[WEAVE BINARY] Frame #{} | Spatial: [{:.4}, {:.4}, {:.4}]",
        frame.seq_id, frame.x, frame.y, frame.z
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_close(left: f64, right: f64) {
        assert!((left - right).abs() < 1e-12, "left={left}, right={right}");
    }

    #[test]
    fn init_with_default_state_matches_legacy_init() {
        let mut default_frame = SpatiotemporalFrame {
            seq_id: 0,
            x: 0.0,
            y: 0.0,
            z: 0.0,
            u: 0.0,
            v: 0.0,
            w: 0.0,
            fluidity: 0.0,
            drag: 0.0,
            divergence: 0.0,
            payload: [0; 16],
        };
        let mut state_frame = default_frame;

        unsafe {
            chaos_engine_init(10.0, 28.0, 8.33333333333);
            weave_spatiotemporal_frame(1, ptr::null(), &mut default_frame);

            chaos_engine_init_with_state(10.0, 28.0, 8.33333333333, 0.1, 0.0, 0.0);
            weave_spatiotemporal_frame(1, ptr::null(), &mut state_frame);
        }

        assert_close(default_frame.x, state_frame.x);
        assert_close(default_frame.y, state_frame.y);
        assert_close(default_frame.z, state_frame.z);
    }

    #[test]
    fn custom_state_changes_emitted_frame() {
        let mut custom_frame = SpatiotemporalFrame {
            seq_id: 0,
            x: 0.0,
            y: 0.0,
            z: 0.0,
            u: 0.0,
            v: 0.0,
            w: 0.0,
            fluidity: 0.0,
            drag: 0.0,
            divergence: 0.0,
            payload: [0; 16],
        };
        let mut baseline_frame = custom_frame;

        unsafe {
            chaos_engine_init_with_state(10.0, 28.0, 8.33333333333, 1.0, 1.0, 1.0);
            weave_spatiotemporal_frame(2, ptr::null(), &mut custom_frame);

            chaos_engine_init(10.0, 28.0, 8.33333333333);
            weave_spatiotemporal_frame(2, ptr::null(), &mut baseline_frame);
        }

        assert!(
            (custom_frame.x - baseline_frame.x).abs() > 1e-9
                || (custom_frame.y - baseline_frame.y).abs() > 1e-9
                || (custom_frame.z - baseline_frame.z).abs() > 1e-9
        );
    }
}
