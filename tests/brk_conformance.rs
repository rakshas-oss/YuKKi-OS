use yukkios::gpu_adapter::{
    decode_brk1_frame, decode_brk1_response_frame, encode_brk1_frame, Brk1Frame,
    BRK1_MSG_REQUEST,
};
use yukkios::{decode_brk2_frame, Brk2BrokerRequest, Brk2Limits};

const CORPUS: &str = include_str!("fixtures/protocol/brk-conformance-v1.corpus");

fn unhex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("corpus hex"))
        .collect()
}

#[test]
fn shared_brk1_brk2_conformance_corpus() {
    let mut count = 0usize;
    for line in CORPUS.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }

        let columns: Vec<_> = line.split('|').collect();
        assert_eq!(columns.len(), 5, "bad corpus row: {line}");
        let (id, protocol, direction, expected) =
            (columns[0], columns[1], columns[2], columns[3]);
        let body = unhex(columns[4]);
        let should_accept = expected == "accept";

        let accepted = match (protocol, direction) {
            ("BRK1", "request") => {
                let decoded = decode_brk1_frame(&body);
                if id == "brk1-request-valid" {
                    let request = decoded.as_ref().expect("valid BRK1 request");
                    assert_eq!(request.task_id, "t");
                    assert_eq!(request.source, "y");
                    assert_eq!(request.destination, "o");
                    assert_eq!(request.kind, "k");
                    assert_eq!(request.priority, 1);
                    assert_eq!(request.timeout_ms, 3000);
                    assert_eq!(request.payload, vec![0xaa, 0xbb]);

                    let encoded = encode_brk1_frame(&Brk1Frame {
                        msg_type: BRK1_MSG_REQUEST,
                        task_id: "t".into(),
                        source: "y".into(),
                        destination: "o".into(),
                        kind: "k".into(),
                        priority: 1,
                        timeout_ms: 3000,
                        payload: vec![0xaa, 0xbb],
                    })
                    .expect("encode BRK1");
                    assert_eq!(encoded, body, "BRK1 canonical encoding drift");
                }
                decoded.is_ok()
            }
            ("BRK1", "response") => {
                let decoded = decode_brk1_response_frame(&body);
                if id == "brk1-response-valid" {
                    let response = decoded.as_ref().expect("valid BRK1 response");
                    assert_eq!(response.task_id, "t-42");
                    assert_eq!(response.status, 0);
                    assert_eq!(response.selected_gpu, 1);
                    assert_eq!(response.latency_ms, 9);
                    assert_eq!(response.result, b"abc".to_vec());
                }
                decoded.is_ok()
            }
            ("BRK2", "request") => {
                let mut frame = Vec::with_capacity(body.len() + 4);
                frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
                frame.extend_from_slice(&body);
                let decoded = decode_brk2_frame(&frame, Brk2Limits::default());
                if let Ok(message) = decoded.as_ref() {
                    let request = Brk2BrokerRequest::from_message(message);
                    if id == "brk2-request-valid" {
                        let request = request.as_ref().expect("valid BRK2 request schema");
                        assert_eq!(request.task_id, "conformance-001");
                        assert_eq!(request.source, "yukki");
                        assert_eq!(request.destination, "overhauled");
                        assert_eq!(request.kind, "inference");
                        assert_eq!(request.priority, 7);
                        assert_eq!(request.timeout_ms, 2500);
                        assert_eq!(request.payload, vec![0, 1, 2, 255]);
                        assert_eq!(message.header.request_id, 0x0102030405060708);
                    }
                    request.is_ok()
                } else {
                    false
                }
            }
            _ => panic!("unsupported corpus row: {id}"),
        };

        assert_eq!(
            accepted,
            should_accept,
            "{id}: expected {expected}, got {}",
            if accepted { "accept" } else { "reject" }
        );
        count += 1;
    }
    assert_eq!(count, 17, "unexpected corpus size");
}
