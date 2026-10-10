use std::sync::{Arc, Mutex};
use yukkios_6_8_0_inet3::wasm_ingest::*;

const CH: u64 = 0x98F4_CA01_E5B2_3344;

fn guest_wasm() -> Vec<u8> {
    if let Ok(path) = std::env::var("YUKKI_GUEST_WASM") {
        return std::fs::read(path).expect("read YUKKI_GUEST_WASM");
    }
    // Minimal stand-in: calls the yield import with the channel pointer.
    wat_bytes(
        r#"(module
          (import "env" "wasmtime_yield_xpu" (func $y (param i32 i32) (result i32)))
          (memory (export "memory") 1)
          (func (export "execute_inference_pipeline") (param i32 i32 i32) (result i32)
            local.get 0 i32.const 5000 call $y))"#,
    )
}

fn wat_bytes(wat: &str) -> Vec<u8> {
    wat::parse_str(wat).expect("valid wat")
}

fn handler(log: Arc<Mutex<Vec<(u64, u32)>>>, status: i32) -> XpuHandler {
    Arc::new(move |id, t| {
        log.lock().unwrap().push((id, t));
        status
    })
}

#[test]
fn parses_channel_ids() {
    assert_eq!(parse_channel_id("0x98F4CA01E5B23344"), Ok(CH));
    assert_eq!(parse_channel_id("ff"), Ok(255));
    for bad in ["", "0x", "zz", "0x1_0", "0x00000000000000001"] {
        assert_eq!(parse_channel_id(bad), Err(IngestError::BadChannelId), "{bad}");
    }
}

#[test]
fn channel_ptr_validation() {
    assert_eq!(validate_channel_ptr(65536, 16), Ok(16));
    assert_eq!(validate_channel_ptr(65536, 0), Err(STATUS_BAD_CHANNEL));
    assert_eq!(validate_channel_ptr(65536, 24), Err(STATUS_MISALIGNED));
    assert_eq!(validate_channel_ptr(65536, 65536 - 32), Err(STATUS_BAD_CHANNEL));
    assert_eq!(validate_channel_ptr(65536, u32::MAX - 15), Err(STATUS_BAD_CHANNEL));
}

#[test]
fn rejects_bad_modules() {
    let h = handler(Default::default(), 0);
    assert_eq!(run_guest(b"nope", CH, &[1], h.clone()).unwrap_err(), IngestError::BadMagic);
    let evil = wat_bytes(
        r#"(module (import "env" "evil" (func)) (memory (export "memory") 1)
           (func (export "execute_inference_pipeline") (param i32 i32 i32) (result i32) i32.const 0))"#,
    );
    assert!(matches!(run_guest(&evil, CH, &[1], h.clone()), Err(IngestError::DisallowedImport(_))));
    let noexp = wat_bytes("(module (memory (export \"memory\") 1))");
    assert_eq!(run_guest(&noexp, CH, &[1], h.clone()).unwrap_err(), IngestError::MissingExport);
    assert_eq!(run_guest(&vec![0u8; MAX_MODULE_BYTES + 1], CH, &[1], h).unwrap_err(), IngestError::TooLarge);
}

#[test]
fn runs_guest_through_bridge() {
    let log = Arc::new(Mutex::new(vec![]));
    let r = run_guest(&guest_wasm(), CH, &[1, 2, 3, 4], handler(log.clone(), 0)).unwrap();
    assert_eq!(r, 0);
    assert_eq!(log.lock().unwrap().as_slice(), &[(CH, 5000)]);
}

#[test]
fn bridge_passes_through_status() {
    let r = run_guest(&guest_wasm(), CH, &[1], handler(Default::default(), -6)).unwrap();
    assert_eq!(r, -6);
}

#[test]
fn bridge_rejects_wild_pointer() {
    let wasm = wat_bytes(
        r#"(module
          (import "env" "wasmtime_yield_xpu" (func $y (param i32 i32) (result i32)))
          (memory (export "memory") 1)
          (func (export "execute_inference_pipeline") (param i32 i32 i32) (result i32)
            i32.const -16 i32.const 5000 call $y))"#,
    );
    let log = Arc::new(Mutex::new(vec![]));
    assert_eq!(run_guest(&wasm, CH, &[1], handler(log.clone(), 0)).unwrap(), STATUS_BAD_CHANNEL);
    assert!(log.lock().unwrap().is_empty());
}

#[test]
fn fuel_exhaustion_is_bounded() {
    let wasm = wat_bytes(
        r#"(module
          (import "env" "wasmtime_yield_xpu" (func (param i32 i32) (result i32)))
          (memory (export "memory") 1)
          (func (export "execute_inference_pipeline") (param i32 i32 i32) (result i32)
            (loop br 0) i32.const 0))"#,
    );
    assert!(matches!(
        run_guest(&wasm, CH, &[1], handler(Default::default(), 0)),
        Err(IngestError::Execution(_))
    ));
}

#[test]
fn deploy_handler_statuses() {
    let h = handler(Default::default(), 0);
    let w = guest_wasm();
    let ok = |ct, ch, b: &[u8]| handle_deploy(ct, ch, b, h.clone()).status;
    assert_eq!(ok(Some("application/wasm"), Some("0x98F4CA01E5B23344"), &w), 200);
    assert_eq!(ok(Some("text/plain"), Some("0x1"), &w), 415);
    assert_eq!(ok(None, Some("0x1"), &w), 415);
    assert_eq!(ok(Some("application/wasm"), None, &w), 400);
    assert_eq!(ok(Some("application/wasm"), Some("xyz"), &w), 400);
    assert_eq!(ok(Some("application/wasm"), Some("0x1"), b"garbage"), 422);
    assert_eq!(ok(Some("application/wasm"), Some("0x1"), &vec![0u8; MAX_MODULE_BYTES + 1]), 413);
}
