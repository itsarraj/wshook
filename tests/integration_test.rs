use futures_util::StreamExt;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use wshook::signature::sign_hmac_sha256;
use wshook::{run_http2ws, run_ws2http, Http2WsConfig, Ws2HttpConfig};

#[tokio::test]
async fn test_http2ws_broadcast() {
    let config = Http2WsConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        http_path: "/webhook".to_string(),
        ws_path: "/ws".to_string(),
        secret: None,
        buffer_size: 0,
        quiet: true,
    };

    let server = run_http2ws(config).await.expect("Failed to start http2ws");
    let addr = server.local_addr();

    // 1. Connect a WebSocket client
    let ws_url = format!("ws://{}/ws", addr);
    let (mut ws_stream, _) = connect_async(&ws_url).await.expect("WS connect failed");

    // 2. Post an HTTP webhook
    let client = reqwest::Client::new();
    let http_url = format!("http://{}/webhook", addr);
    let payload = r#"{"event":"user.signup","id":42}"#;

    let resp = client
        .post(&http_url)
        .header("Content-Type", "application/json")
        .body(payload)
        .send()
        .await
        .expect("HTTP post failed");

    assert_eq!(resp.status(), 200);

    // 3. Verify WebSocket client received the broadcast message
    let timeout = Duration::from_secs(2);
    let msg = tokio::time::timeout(timeout, ws_stream.next())
        .await
        .expect("Timed out waiting for WS message")
        .expect("Stream closed")
        .expect("WS error");

    assert_eq!(msg, Message::Text(payload.to_string()));

    server.shutdown();
}

#[tokio::test]
async fn test_http2ws_hmac_verification() {
    let secret = "super_secret_bridge_key";
    let config = Http2WsConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        http_path: "/webhook".to_string(),
        ws_path: "/ws".to_string(),
        secret: Some(secret.to_string()),
        buffer_size: 0,
        quiet: true,
    };

    let server = run_http2ws(config).await.expect("Failed to start http2ws");
    let addr = server.local_addr();
    let http_url = format!("http://{}/webhook", addr);
    let client = reqwest::Client::new();
    let payload = r#"{"event":"payment.succeeded","amount":100}"#;

    // 1. Post without signature -> Expect 401
    let resp_no_sig = client
        .post(&http_url)
        .body(payload)
        .send()
        .await
        .expect("HTTP send");
    assert_eq!(resp_no_sig.status(), 401);

    // 2. Post with invalid signature -> Expect 401
    let resp_bad_sig = client
        .post(&http_url)
        .header("X-Hub-Signature-256", "sha256=invalidhex123")
        .body(payload)
        .send()
        .await
        .expect("HTTP send");
    assert_eq!(resp_bad_sig.status(), 401);

    // 3. Post with valid HMAC signature -> Expect 200
    let valid_sig = sign_hmac_sha256(secret.as_bytes(), payload.as_bytes());
    let resp_valid = client
        .post(&http_url)
        .header("X-Hub-Signature-256", format!("sha256={}", valid_sig))
        .body(payload)
        .send()
        .await
        .expect("HTTP send");
    assert_eq!(resp_valid.status(), 200);

    server.shutdown();
}

#[tokio::test]
async fn test_http2ws_buffer_replay() {
    let config = Http2WsConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        http_path: "/webhook".to_string(),
        ws_path: "/ws".to_string(),
        secret: None,
        buffer_size: 2,
        quiet: true,
    };

    let server = run_http2ws(config).await.expect("Failed to start http2ws");
    let addr = server.local_addr();
    let http_url = format!("http://{}/webhook", addr);
    let client = reqwest::Client::new();

    // Send 3 events (buffer size is 2, so event 1 should be evicted)
    for i in 1..=3 {
        let resp = client
            .post(&http_url)
            .body(format!("event_{}", i))
            .send()
            .await
            .expect("HTTP post failed");
        assert_eq!(resp.status(), 200);
    }

    // Now connect a new WebSocket client
    let ws_url = format!("ws://{}/ws", addr);
    let (mut ws_stream, _) = connect_async(&ws_url).await.expect("WS connect failed");

    // Client should receive replayed event_2 and event_3
    let msg1 = tokio::time::timeout(Duration::from_secs(1), ws_stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(msg1, Message::Text("event_2".to_string()));

    let msg2 = tokio::time::timeout(Duration::from_secs(1), ws_stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(msg2, Message::Text("event_3".to_string()));

    server.shutdown();
}

#[tokio::test]
async fn test_ws2http_forwarding() {
    // 1. Mock HTTP Webhook target server
    let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = http_listener.local_addr().unwrap();
    let received_bodies = Arc::new(Mutex::new(Vec::new()));
    let received_signatures = Arc::new(Mutex::new(Vec::new()));

    let rec_b = Arc::clone(&received_bodies);
    let rec_s = Arc::clone(&received_signatures);

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = http_listener.accept().await {
            let mut buf = vec![0u8; 4096];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            if n > 0 {
                let req_str = String::from_utf8_lossy(&buf[..n]);
                if let Some((headers, body)) = req_str.split_once("\r\n\r\n") {
                    rec_b.lock().unwrap().push(body.to_string());
                    for line in headers.lines() {
                        if line.to_lowercase().starts_with("x-hub-signature-256:") {
                            rec_s.lock().unwrap().push(line.to_string());
                        }
                    }
                }
                let resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
                let _ = stream.write_all(resp.as_bytes()).await;
            }
        }
    });

    // 2. Mock WebSocket server
    let ws_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ws_addr = ws_listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((stream, _)) = ws_listener.accept().await {
            if let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await {
                use futures_util::SinkExt;
                tokio::time::sleep(Duration::from_millis(50)).await;
                let _ = ws
                    .send(Message::Text(r#"{"data":{"message":"hello_world"}}"#.to_string()))
                    .await;
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    });

    // 3. Start ws2http bridge
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let secret_key = "test_signing_secret";

    let ws2http_cfg = Ws2HttpConfig {
        ws_url: format!("ws://{}", ws_addr),
        target_url: format!("http://{}/webhook", http_addr),
        secret: Some(secret_key.to_string()),
        headers: vec![("X-Custom-Source".to_string(), "wshook-test".to_string())],
        filter: None,
        extract: Some("data.message".to_string()),
        retries: 2,
        retry_delay_ms: 100,
        reconnect_interval_ms: 500,
        concurrency: 2,
        timeout_secs: 2,
        quiet: true,
    };

    tokio::spawn(async move {
        let _ = run_ws2http(ws2http_cfg, shutdown_rx).await;
    });

    // Wait up to 1 second for forwarding to complete
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_millis(1500) {
        if !received_bodies.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let bodies = received_bodies.lock().unwrap().clone();
    assert_eq!(bodies.len(), 1, "Should have received 1 forwarded webhook");
    assert_eq!(bodies[0], "hello_world");

    let sigs = received_signatures.lock().unwrap().clone();
    assert_eq!(sigs.len(), 1, "Should have received HMAC signature");
    assert!(sigs[0].contains("sha256="));

    let _ = shutdown_tx.send(true);
}
