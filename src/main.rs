use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use std::net::SocketAddr;
use tokio::sync::watch;
use wshook::{run_http2ws, run_ws2http, Http2WsConfig, Ws2HttpConfig};

#[derive(Parser, Debug)]
#[command(
    name = "wshook",
    author = "Animesh Raj <animesh080808@gmail.com>",
    version,
    about = "A bi-directional bridge between WebSockets and HTTP Webhooks with HMAC signing, retries, and broadcast",
    after_help = "EXAMPLES:\n  \
      wshook ws2http --ws wss://stream.binance.com/ws/btcusdt@trade --target http://localhost:3000/api/trade\n  \
      wshook ws2http --ws ws://127.0.0.1:8080/events --target http://localhost:8000/webhook --secret my_hmac_secret\n  \
      wshook http2ws --listen 0.0.0.0:9000 --http-path /ingest --ws-path /stream\n  \
      wshook http2ws --listen 127.0.0.1:8080 --secret webhook_secret_key --buffer-size 10"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Stream WebSocket events and forward them as HTTP POST Webhooks
    Ws2http {
        /// Upstream WebSocket URL (e.g. wss://example.com/events)
        #[arg(long)]
        ws: String,

        /// Target HTTP endpoint URL (e.g. http://localhost:3000/webhook)
        #[arg(long)]
        target: String,

        /// Shared secret to compute X-Hub-Signature-256 HMAC header
        #[arg(long)]
        secret: Option<String>,

        /// Custom HTTP header in 'Header: Value' format (repeatable)
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,

        /// Only forward WebSocket messages whose payload matches this regex
        #[arg(long)]
        filter: Option<String>,

        /// Extract JSON dot-path field from payload before forwarding (e.g. data.event)
        #[arg(long)]
        extract: Option<String>,

        /// Number of retries on HTTP delivery failure
        #[arg(long, default_value_t = 3)]
        retries: usize,

        /// Delay in milliseconds between HTTP retry attempts
        #[arg(long, default_value_t = 500)]
        retry_delay_ms: u64,

        /// Reconnect interval in milliseconds if WebSocket disconnects
        #[arg(long, default_value_t = 2000)]
        reconnect_interval_ms: u64,

        /// Maximum concurrent HTTP POST requests in-flight
        #[arg(long, default_value_t = 10)]
        concurrency: usize,

        /// HTTP request timeout in seconds
        #[arg(long, default_value_t = 10)]
        timeout_secs: u64,

        /// Suppress status messages to stderr
        #[arg(short, long)]
        quiet: bool,
    },

    /// Receive incoming HTTP POST Webhooks and broadcast to connected WebSocket clients
    Http2ws {
        /// Socket address to listen on
        #[arg(short, long, default_value = "127.0.0.1:8080")]
        listen: SocketAddr,

        /// HTTP POST endpoint path for receiving webhooks
        #[arg(long, default_value = "/webhook")]
        http_path: String,

        /// WebSocket endpoint path for clients to connect
        #[arg(long, default_value = "/ws")]
        ws_path: String,

        /// Shared secret: if specified, validates incoming X-Hub-Signature-256
        #[arg(long)]
        secret: Option<String>,

        /// Number of recent webhook payloads to buffer and replay to new WebSocket clients
        #[arg(long, default_value_t = 0)]
        buffer_size: usize,

        /// Suppress status messages to stderr
        #[arg(short, long)]
        quiet: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Setup Ctrl+C handler
    let s_tx = shutdown_tx.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = s_tx.send(true);
    });

    match cli.command {
        Commands::Ws2http {
            ws,
            target,
            secret,
            headers,
            filter,
            extract,
            retries,
            retry_delay_ms,
            reconnect_interval_ms,
            concurrency,
            timeout_secs,
            quiet,
        } => {
            let mut header_pairs = Vec::new();
            for h in headers {
                if let Some((k, v)) = h.split_once(':') {
                    header_pairs.push((k.trim().to_string(), v.trim().to_string()));
                } else {
                    bail!("Invalid header '{}', expected 'Header: Value'", h);
                }
            }

            let config = Ws2HttpConfig {
                ws_url: ws,
                target_url: target,
                secret,
                headers: header_pairs,
                filter,
                extract,
                retries,
                retry_delay_ms,
                reconnect_interval_ms,
                concurrency,
                timeout_secs,
                quiet,
            };

            run_ws2http(config, shutdown_rx).await?;
        }
        Commands::Http2ws {
            listen,
            http_path,
            ws_path,
            secret,
            buffer_size,
            quiet,
        } => {
            let config = Http2WsConfig {
                listen,
                http_path: http_path.clone(),
                ws_path: ws_path.clone(),
                secret,
                buffer_size,
                quiet,
            };

            let server = run_http2ws(config).await?;

            if !quiet {
                eprintln!(
                    "{} listening on http://{} (Webhook POST: {}, WebSocket: {})",
                    "wshook http2ws".bold().green(),
                    server.local_addr().to_string().cyan(),
                    http_path.yellow(),
                    ws_path.yellow()
                );
                eprintln!("Press Ctrl+C to shut down.");
            }

            tokio::signal::ctrl_c().await.context("Failed to wait for Ctrl+C")?;

            if !quiet {
                eprintln!("\n{}", "Shutting down wshook...".yellow());
            }
            server.shutdown();
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        }
    }

    Ok(())
}
