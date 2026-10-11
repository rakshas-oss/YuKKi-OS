use std::{sync::Arc, time::Duration};

use futures_util::{SinkExt, StreamExt};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{
        client::IntoClientRequest,
        http::{header::AUTHORIZATION, HeaderValue},
        Message,
    },
};
use yukkios_6_8_0_inet3::{
    stream_gateway::{serve, GatewayAuth},
    LiveMediaStreams, MediaChunk, MediaStreamConfig, MediaStreamMetadata, MediaType,
    StreamRegistry,
};

const TOKEN: &str = "test-gateway-token";

async fn http_get(address: std::net::SocketAddr, path: &str, auth: bool) -> String {
    let mut socket = TcpStream::connect(address).await.unwrap();
    let authorization = if auth {
        ["Authorization: Bearer ", TOKEN, "\r\n"].concat()
    } else {
        String::new()
    };
    socket
        .write_all(
            format!(
                "GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n{authorization}\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(3), socket.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    String::from_utf8(response).unwrap()
}

#[tokio::test]
async fn authenticated_http_and_websocket_stream_with_ack() {
    let streams = Arc::new(LiveMediaStreams::new(MediaStreamConfig::default()).unwrap());
    streams
        .open_stream(MediaStreamMetadata {
            stream_id: "camera-1".into(),
            media_type: MediaType::Video,
            codec: "raw".into(),
        })
        .unwrap();
    streams
        .append_chunk(
            "camera-1",
            MediaChunk {
                stream_id: "camera-1".into(),
                media_type: MediaType::Video,
                codec: "raw".into(),
                sequence_no: 0,
                timestamp_ms: 0,
                is_keyframe: true,
                payload: vec![1, 2, 3],
            },
        )
        .unwrap();
    let registry = StreamRegistry::new("node-a", streams.clone()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(serve(
        listener,
        streams.clone(),
        registry,
        GatewayAuth::Bearer(TOKEN.into()),
    ));

    assert!(http_get(address, "/v1/streams", false)
        .await
        .starts_with("HTTP/1.1 401"));
    let list = http_get(address, "/v1/streams", true).await;
    assert!(list.starts_with("HTTP/1.1 200"));
    assert!(list.contains("camera-1"));
    assert!(http_get(address, "/v1/streams/camera-1", true)
        .await
        .starts_with("HTTP/1.1 200"));
    let chunks = http_get(address, "/v1/streams/camera-1/chunks?from=0", true).await;
    assert!(chunks.starts_with("HTTP/1.1 200"));
    assert!(chunks.contains("\"sequence_no\":0"));

    let url = format!("ws://{address}/v1/streams/camera-1/ws?from=0");
    let mut unauthorized = url.clone().into_client_request().unwrap();
    unauthorized.headers_mut().remove(AUTHORIZATION);
    assert!(connect_async(unauthorized).await.is_err());

    let mut request = url.into_client_request().unwrap();
    request.headers_mut().insert(
        AUTHORIZATION,
        HeaderValue::from_str(&["Bearer ", TOKEN].concat()).unwrap(),
    );
    let (mut websocket, _) = timeout(Duration::from_secs(3), connect_async(request))
        .await
        .unwrap()
        .unwrap();
    let frame = timeout(Duration::from_secs(3), websocket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .into_data();
    assert_eq!(u64::from_be_bytes(frame[..8].try_into().unwrap()), 0);
    assert_eq!(
        MediaChunk::decode(&frame[8..]).unwrap().payload,
        vec![1, 2, 3]
    );

    websocket
        .send(Message::Text(
            serde_json::json!({"type": "ack", "sequence": 0})
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    streams.close_stream("camera-1").unwrap();
    assert!(matches!(
        timeout(Duration::from_secs(3), websocket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        Message::Close(_)
    ));
    server.abort();
}
