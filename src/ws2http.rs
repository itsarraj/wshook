use crate::signature::sign_hmac_sha256;
use anyhow::{Context, Result};
use chrono::Utc;
use colored::Colorize;
use futures_util::StreamExt;
use regex::Regex;
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{watch, Semaphore};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

#[derive(Debug, Clone)]
pub struct Ws2HttpConfig {
    pub ws_url: String,
    pub target_url: String,
    pub secret: Option<String>,
    pub headers: Vec<(String, String)>,
    pub filter: Option<String>,
    pub extract: Option<String>,
    pub retries: usize,
    pub retry_delay_ms: u64,
    pub reconnect_interval_ms: u64,
    pub concurrency: usize,
    pub timeout_secs: u64,
    pub quiet: bool,
}

pub async fn run_ws2http(
    config: Ws2HttpConfig,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    let filter_regex = if let Some(ref p) = config.filter {
        Some(Regex::new(p).with_context(|| format!("Invalid filter regex '{}'", p))?)
    } else {
        None
    };

    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(config.timeout_secs))
        .build()?;

    let config = Arc::new(config);
    let http_client = Arc::new(http_client);
    let semaphore = Arc::new(Semaphore::new(config.concurrency));

    while !*shutdown_rx.borrow() {
        if !config.quiet {
            eprintln!(
                "{} connecting to WebSocket {}",
                "wshook ws2http".bold().green(),
                config.ws_url.cyan()
            );
        }

        let ws_res = connect_async(&config.ws_url).await;
        let ws_stream = match ws_res {
            Ok((stream, _)) => {
                if !config.quiet {
                    eprintln!(
                        "{} connected to {}, streaming to {}",
                        "wshook ws2http".bold().green(),
                        config.ws_url.cyan(),
                        config.target_url.yellow()
                    );
                }
                stream
            }
            Err(e) => {
                eprintln!(
                    "{} connection failed: {}. Retrying in {}ms...",
                    "wshook".bold().red(),
                    e,
                    config.reconnect_interval_ms
                );
                tokio::select! {
                    _ = shutdown_rx.changed() => break,
                    _ = tokio::time::sleep(Duration::from_millis(config.reconnect_interval_ms)) => continue,
                }
            }
        };

        let (_, mut ws_reader) = ws_stream.split();

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        return Ok(());
                    }
                }
                msg_opt = ws_reader.next() => {
                    match msg_opt {
                        Some(Ok(Message::Text(text))) => {
                            // Filter check
                            if let Some(ref re) = filter_regex {
                                if !re.is_match(&text) {
                                    continue;
                                }
                            }

                            // Extract check
                            let payload = if let Some(ref dotpath) = config.extract {
                                match serde_json::from_str::<Value>(&text) {
                                    Ok(v) => {
                                        if let Some(sub) = extract_dotpath(&v, dotpath) {
                                            match sub {
                                                Value::String(s) => s.as_bytes().to_vec(),
                                                other => other.to_string().into_bytes(),
                                            }
                                        } else {
                                            continue;
                                        }
                                    }
                                    Err(_) => continue,
                                }
                            } else {
                                text.into_bytes()
                            };

                            let cfg = Arc::clone(&config);
                            let client = Arc::clone(&http_client);
                            let sem = Arc::clone(&semaphore);

                            tokio::spawn(async move {
                                let _permit = sem.acquire().await;
                                forward_http_request(cfg, client, payload, true).await;
                            });
                        }
                        Some(Ok(Message::Binary(bin))) => {
                            let cfg = Arc::clone(&config);
                            let client = Arc::clone(&http_client);
                            let sem = Arc::clone(&semaphore);

                            tokio::spawn(async move {
                                let _permit = sem.acquire().await;
                                forward_http_request(cfg, client, bin, false).await;
                            });
                        }
                        Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => {}
                        Some(Ok(Message::Close(_))) => {
                            if !config.quiet {
                                eprintln!("{} WebSocket closed by upstream", "wshook".bold().yellow());
                            }
                            break;
                        }
                        Some(Err(e)) => {
                            eprintln!("{} WebSocket error: {}", "wshook".bold().red(), e);
                            break;
                        }
                        None => {
                            if !config.quiet {
                                eprintln!("{} WebSocket disconnected", "wshook".bold().yellow());
                            }
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }

        if *shutdown_rx.borrow() {
            break;
        }

        tokio::select! {
            _ = shutdown_rx.changed() => break,
            _ = tokio::time::sleep(Duration::from_millis(config.reconnect_interval_ms)) => {}
        }
    }

    Ok(())
}

async fn forward_http_request(
    config: Arc<Ws2HttpConfig>,
    client: Arc<reqwest::Client>,
    body: Vec<u8>,
    is_text: bool,
) {
    let mut attempts = 0;
    let max_attempts = 1 + config.retries;

    while attempts < max_attempts {
        attempts += 1;
        let mut req = client.post(&config.target_url);

        if is_text {
            req = req.header("Content-Type", "application/json");
        } else {
            req = req.header("Content-Type", "application/octet-stream");
        }

        for (k, v) in &config.headers {
            req = req.header(k, v);
        }

        if let Some(ref sec) = config.secret {
            let sig = sign_hmac_sha256(sec.as_bytes(), &body);
            let ts = Utc::now().to_rfc3339();
            req = req
                .header("X-Hub-Signature-256", format!("sha256={}", sig))
                .header("X-Webhook-Timestamp", ts);
        }

        req = req.body(body.clone());

        match req.send().await {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    if !config.quiet {
                        eprintln!(
                            "{} forwarded -> HTTP {} ({} bytes)",
                            "wshook".bold().green(),
                            status.as_str().green(),
                            body.len()
                        );
                    }
                    return;
                } else {
                    if !config.quiet {
                        eprintln!(
                            "{} target returned HTTP {} (attempt {}/{})",
                            "wshook".bold().yellow(),
                            status.as_str().red(),
                            attempts,
                            max_attempts
                        );
                    }
                }
            }
            Err(e) => {
                if !config.quiet {
                    eprintln!(
                        "{} POST error: {} (attempt {}/{})",
                        "wshook".bold().red(),
                        e,
                        attempts,
                        max_attempts
                    );
                }
            }
        }

        if attempts < max_attempts {
            tokio::time::sleep(Duration::from_millis(config.retry_delay_ms)).await;
        }
    }
}

pub fn extract_dotpath<'a>(val: &'a Value, path: &str) -> Option<&'a Value> {
    let parts: Vec<&str> = path.split('.').collect();
    let mut cur = val;

    for part in parts {
        if part.is_empty() {
            continue;
        }
        if let Ok(idx) = part.parse::<usize>() {
            cur = cur.get(idx)?;
        } else {
            cur = cur.get(part)?;
        }
    }
    Some(cur)
}
