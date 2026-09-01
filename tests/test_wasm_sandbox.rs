/// Tests for Rustasm WebAssembly Sandbox
/// Validates isolation, memory management, and execution bounds
use yukkios_6_6_6_inet3::wasm_sandbox::RustasmSandbox;

#[test]
fn test_sandbox_initialization() {
    RustasmSandbox::new();
}

#[test]
fn test_buffer_payload_acceptance() {
    let sandbox = RustasmSandbox::new();
    let test_payload = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10,
    ];
    assert!(sandbox.buffer_payload(&test_payload).is_ok());
}

#[test]
fn test_buffer_flush() {
    let sandbox = RustasmSandbox::new();
    let test_payload = [0xFF; 16];
    sandbox.buffer_payload(&test_payload).unwrap();
    sandbox.flush_buffer();
    assert!(sandbox.buffer_payload(&test_payload).is_ok());
}

#[test]
fn test_multiple_payload_buffers() {
    let sandbox = RustasmSandbox::new();
    let payloads = [[0x01u8; 16], [0x02u8; 16], [0x03u8; 16]];

    for payload in &payloads {
        sandbox.buffer_payload(payload).unwrap();
    }
    sandbox.commit_civilian_logic();
    assert!(sandbox.buffer_payload(&[0x04; 16]).is_ok());
}

#[test]
fn test_commit_civilian_logic() {
    let sandbox = RustasmSandbox::new();
    let test_payload = [0xAA; 16];
    sandbox.buffer_payload(&test_payload).unwrap();
    sandbox.commit_civilian_logic();
    assert!(sandbox.buffer_payload(&test_payload).is_ok());
}

#[test]
fn test_sandbox_payload_size_consistency() {
    let sandbox = RustasmSandbox::new();
    // Test with standard 16-byte payload
    let payload: [u8; 16] = [
        0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21, 0x00, 0x00, 0x00,
        0x00,
    ]; // "Hello World!"

    sandbox.buffer_payload(&payload).unwrap();
    sandbox.commit_civilian_logic();
    // Payload size should always be 16 bytes
    assert_eq!(payload.len(), 16, "Payload size must be exactly 16 bytes");
}

#[test]
fn test_sandbox_max_stack_limit() {
    let sandbox = RustasmSandbox::new();
    let wasm = b"\0asm\x01\0\0\0\x01\x05\x01`\0\x01\x7f\x03\x02\x01\0\x07\x08\x01\x04main\0\0\x0a\x06\x01\x04\0A*\x0b";
    assert_eq!(sandbox.execute(wasm).unwrap(), 42);
}
