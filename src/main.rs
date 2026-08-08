mod ffi {
    use std::ffi::c_double;

    #[repr(C, packed)]
    pub struct SpatiotemporalFrame {
        pub seq_id: u64,
        pub x: c_double,
        pub y: c_double,
        pub z: c_double,
        pub u: c_double,
        pub v: c_double,
        pub w: c_double,
        pub fluidity: f32,
        pub drag: f32,
        pub divergence: c_double,
        pub payload: [u8; 16],
    }

    unsafe extern "C" {
        pub fn chaos_engine_reseed(
            sigma: c_double,
            rho: c_double,
            beta: c_double,
            x0: c_double,
            y0: c_double,
            z0: c_double,
        );
        pub fn weave_spatiotemporal_frame(
            seq: u64,
            payload_src: *const u8,
            out_frame: *mut SpatiotemporalFrame,
        );
    }
}

#[tokio::main]
async fn main() {
    println!("YuKKi OS v6.4.1 — Interim-Crypt Edition");
    println!("Initializing Lorenz chaos engine with runtime seed...");

    unsafe {
        ffi::chaos_engine_reseed(10.0, 28.0, 8.333_333_333_33, 0.1, 0.0, 0.0);

        let seed_payload: [u8; 16] = [0x42, 0x7F, 0xA1, 0x00, 0x00, 0x00, 0x00, 0x00,
                                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut frame = std::mem::zeroed::<ffi::SpatiotemporalFrame>();
        ffi::weave_spatiotemporal_frame(1, seed_payload.as_ptr(), &mut frame);

        // Copy packed fields to locals to avoid misaligned reference UB
        let x = frame.x;
        let y = frame.y;
        let z = frame.z;
        let fluidity = frame.fluidity;

        println!(
            "Frame #1 — x: {:.6}, y: {:.6}, z: {:.6}, fluidity: {:.4}",
            x, y, z, fluidity
        );
    }
}
