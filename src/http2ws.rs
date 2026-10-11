use crate::signature::verify_hmac_sha256;
use anyhow::{Context, Result};
use colored::Colorize;
use futures_util::{SinkExt, StreamExt};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, watch, Mutex};
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;

#[derive(Debug, Clone)]
pub struct Http2WsConfig {
    pub listen: SocketAddr,
    pub http_path: String,
    pub ws_path: String,
    pub secret: Option<String>,
    pub buffer_size: usize,
    pub quiet: bool,
}

pub struct Http2WsServerHandle {
    local_addr: SocketAddr,
    shutdown_tx: watch::Sender<bool>,
}

impl Http2WsServerHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }
}

pub async fn run_http2ws(config: Http2WsConfig) -> Result<Http2WsServerHandle> {
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("Failed to bind to {}", config.listen))?;
    let local_addr = listener.local_addr()?;

    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let (bcast_tx, _) = broadcast::channel::<Arc<Vec<u8>>>(1024);
    let active_ws_clients = Arc::new(AtomicUsize::new(0));
    let replay_buffer = Arc::new(Mutex::new(VecDeque::<Vec<u8>>::new()));
    let config = Arc::new(config);

    let c_cfg = Arc::clone(&config);
    let c_bcast_tx = bcast_tx.clone();
    let c_clients = Arc::clone(&active_ws_clients);
    let c_buffer = Arc::clone(&replay_buffer);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                res = listener.accept() => {
                    match res {
                        Ok((stream, remote_addr)) => {
                            let cfg = Arc::clone(&c_cfg);
                            let bcast_tx = c_bcast_tx.clone();
                            let clients = Arc::clone(&c_clients);
                            let buffer = Arc::clone(&c_buffer);

                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(stream, remote_addr, cfg, bcast_tx, clients, buffer).await {
                                    // Log error if not quiet
                                    eprintln!("[wshook] Error on connection {}: {}", remote_addr, e);
                                }
                            });
                        }
                        Err(e) => {
                            eprintln!("[wshook] Accept error: {}", e);
                        }
                    }
                }
            }
        }
    });

    Ok(Http2WsServerHandle {
        local_addr,
        shutdown_tx,
    })
}

async fn handle_connection(
    stream: TcpStream,
    remote_addr: SocketAddr,
    config: Arc<Http2WsConfig>,
    bcast_tx: broadcast::Sender<Arc<Vec<u8>>>,
    active_clients: Arc<AtomicUsize>,
    replay_buffer: Arc<Mutex<VecDeque<Vec<u8>>>>,
) -> Result<()> {
    let mut peek_buf = [0u8; 1024];
    let n = stream.peek(&mut peek_buf).await?;
    if n == 0 {
        return Ok(());
    }

    let peek_str = String::from_utf8_lossy(&peek_buf[..n]).to_lowercase();
    let is_ws_upgrade = peek_str.contains("upgrade: websocket");

    if is_ws_upgrade {
        // Upgrade to WebSocket
        let ws_stream = accept_async(stream).await?;
        active_clients.fetch_add(1, Ordering::Relaxed);
        if !config.quiet {
            eprintln!(
                "{} WebSocket client connected from {} (total: {})",
                "wshook http2ws".bold().green(),
                remote_addr,
                active_clients.load(Ordering::Relaxed)
            );
        }

        let (mut ws_sender, mut ws_receiver) = ws_stream.split();
        let mut bcast_rx = bcast_tx.subscribe();

        // If replay buffer has messages, send them to the new client
        if config.buffer_size > 0 {
            let buf = replay_buffer.lock().await;
            for msg in buf.iter() {
                let ws_msg = match std::str::from_utf8(msg) {
                    Ok(s) => Message::Text(s.to_string()),
                    Err(_) => Message::Binary(msg.clone()),
                };
                if ws_sender.send(ws_msg).await.is_err() {
                    break;
                }
            }
        }

        tokio::select! {
            // Forward broadcast messages to this WebSocket client
            _ = async {
                while let Ok(msg_arc) = bcast_rx.recv().await {
                    let ws_msg = match std::str::from_utf8(&msg_arc) {
                        Ok(s) => Message::Text(s.to_string()),
                        Err(_) => Message::Binary((*msg_arc).clone()),
                    };
                    if ws_sender.send(ws_msg).await.is_err() {
                        break;
                    }
                }
            } => {}
            // Read client messages (keep-alive, pong, or disconnect)
            _ = async {
                use futures_util::StreamExt;
                while let Some(msg_res) = ws_receiver.next().await {
                    match msg_res {
                        Ok(Message::Close(_)) | Err(_) => break,
                        _ => {}
                    }
                }
            } => {}
        }

        active_clients.fetch_sub(1, Ordering::Relaxed);
        if !config.quiet {
            eprintln!(
                "{} WebSocket client disconnected: {}",
                "wshook http2ws".bold().yellow(),
                remote_addr
            );
        }
    } else {
        // Handle regular HTTP request
        handle_http_request(stream, config, bcast_tx, active_clients, replay_buffer).await?;
    }

    Ok(())
}

async fn handle_http_request(
    mut stream: TcpStream,
    config: Arc<Http2WsConfig>,
    bcast_tx: broadcast::Sender<Arc<Vec<u8>>>,
    active_clients: Arc<AtomicUsize>,
    replay_buffer: Arc<Mutex<VecDeque<Vec<u8>>>>,
) -> Result<()> {
    let mut header_buf = Vec::new();
    let mut temp = [0u8; 1024];

    // Read headers until \r\n\r\n
    let (header_len, _) = loop {
        let n = stream.read(&mut temp).await?;
        if n == 0 {
            return Ok(());
        }
        header_buf.extend_from_slice(&temp[..n]);
        if let Some(pos) = header_buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break (pos + 4, pos);
        }
        if header_buf.len() > 65536 {
            send_http_response(&mut stream, 431, "Request Header Fields Too Large").await?;
            return Ok(());
        }
    };

    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    let status = req.parse(&header_buf[..header_len])?;
    if !status.is_complete() {
        send_http_response(&mut stream, 400, "Bad Request").await?;
        return Ok(());
    }

    let method = req.method.unwrap_or("");
    let path = req.path.unwrap_or("");

    if method != "POST" {
        send_http_response(&mut stream, 405, "Method Not Allowed").await?;
        return Ok(());
    }

    // Check path (strip query params if any)
    let clean_path = path.split('?').next().unwrap_or(path);
    if clean_path != config.http_path {
        send_http_response(&mut stream, 404, "Not Found").await?;
        return Ok(());
    }

    // Determine Content-Length
    let content_length: usize = req
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("content-length"))
        .and_then(|h| std::str::from_utf8(h.value).ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // Read remaining body
    let mut body = Vec::with_capacity(content_length);
    let already_read_body = &header_buf[header_len..];
    body.extend_from_slice(already_read_body);

    while body.len() < content_length {
        let to_read = (content_length - body.len()).min(temp.len());
        let n = stream.read(&mut temp[..to_read]).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&temp[..n]);
    }

    // Validate HMAC signature if secret is configured
    if let Some(ref sec) = config.secret {
        let sig_header = req
            .headers
            .iter()
            .find(|h| {
                h.name.eq_ignore_ascii_case("x-hub-signature-256")
                    || h.name.eq_ignore_ascii_case("x-signature-256")
            })
            .and_then(|h| std::str::from_utf8(h.value).ok());

        match sig_header {
            Some(sig) => {
                if !verify_hmac_sha256(sec.as_bytes(), &body, sig) {
                    send_http_response(&mut stream, 401, "Invalid HMAC Signature").await?;
                    return Ok(());
                }
            }
            None => {
                send_http_response(&mut stream, 401, "Missing Signature Header").await?;
                return Ok(());
            }
        }
    }

    let client_count = active_clients.load(Ordering::Relaxed);

    // Broadcast to WebSocket clients
    let body_arc = Arc::new(body.clone());
    let _ = bcast_tx.send(body_arc);

    // Add to replay buffer if configured
    if config.buffer_size > 0 {
        let mut buf = replay_buffer.lock().await;
        if buf.len() >= config.buffer_size {
            buf.pop_front();
        }
        buf.push_back(body.clone());
    }

    if !config.quiet {
        eprintln!(
            "{} received webhook ({} bytes) -> broadcasted to {} WebSocket client(s)",
            "wshook http2ws".bold().green(),
            body.len(),
            client_count
        );
    }

    let response_body = format!(
        r#"{{"status":"broadcasted","clients":{},"bytes":{}}}"#,
        client_count,
        body.len()
    );

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        response_body.len(),
        response_body
    );

    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;

    Ok(())
}

async fn send_http_response(stream: &mut TcpStream, status: u16, msg: &str) -> Result<()> {
    let body = format!(r#"{{"error":"{}"}}"#, msg);
    let resp = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        msg,
        body.len(),
        body
    );
    stream.write_all(resp.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}
