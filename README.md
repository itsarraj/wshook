# wshook

A bi-directional bridge between WebSockets and HTTP Webhooks with HMAC signing, retries, and broadcast.

`wshook` connects real-time streaming architectures to event-driven HTTP architectures. It eliminates the need to build and deploy custom cloud functions or adapter services just to translate between WebSocket feeds and HTTP Webhooks.

## Operating Modes

1. **`ws2http` (WebSocket to Webhook)**:
   - Connects to an upstream WebSocket server (e.g. financial market feeds, IoT telemetry, chat events).
   - Translates incoming WebSocket frames into HTTP POST requests sent to a target URL.
   - Automatically signs payloads using HMAC-SHA256 (`X-Hub-Signature-256: sha256=...`).
   - Supports regex filtering, JSON dot-path field extraction, configurable concurrency, and automatic reconnection with retry backoff.

2. **`http2ws` (Webhook to WebSocket)**:
   - Listens on a single socket address for both incoming HTTP Webhook POSTs and real-time WebSocket clients.
   - Incoming webhook payloads are instantly fanned out to all connected WebSocket clients.
   - Validates incoming `X-Hub-Signature-256` or `X-Signature-256` HMAC headers with `--secret`.
   - Supports an in-memory replay buffer (`--buffer-size`) so newly connecting WebSocket clients immediately receive the last $N$ events.

## Installation

```bash
cargo install --path .
```

## Quick Start

### 1. Forward WebSocket Stream to an Internal Webhook Endpoint

```bash
wshook ws2http \
  --ws wss://stream.binance.com/ws/btcusdt@trade \
  --target http://localhost:3000/api/webhooks/trade \
  --secret "my_webhook_secret_key"
```

### 2. Filter and Extract Fields from WebSocket Before Forwarding

```bash
wshook ws2http \
  --ws ws://127.0.0.1:8080/events \
  --target http://localhost:8000/alerts \
  --filter '"status":\s*"CRITICAL"' \
  --extract data.alert \
  --retries 5
```

### 3. Broadcast Incoming HTTP Webhooks to Browser/WebSocket Clients

```bash
wshook http2ws \
  --listen 0.0.0.0:8080 \
  --http-path /webhook \
  --ws-path /ws \
  --secret "stripe_webhook_secret" \
  --buffer-size 10
```

Now POST to `http://localhost:8080/webhook` and immediately receive the event on `ws://localhost:8080/ws`.

## Command-Line Options

### `wshook ws2http`

```text
Usage: wshook ws2http [OPTIONS] --ws <WS> --target <TARGET>

Options:
      --ws <WS>                                Upstream WebSocket URL
      --target <TARGET>                        Target HTTP endpoint URL
      --secret <SECRET>                        Shared secret for X-Hub-Signature-256
  -H, --header <HEADER>                        Custom HTTP header 'Header: Value' (repeatable)
      --filter <REGEX>                         Only forward messages matching regex
      --extract <DOTPATH>                      Extract JSON dot-path field before forwarding
      --retries <RETRIES>                      Retries on HTTP failure [default: 3]
      --retry-delay-ms <MS>                    Delay between HTTP retries [default: 500]
      --reconnect-interval-ms <MS>             WebSocket reconnect delay [default: 2000]
      --concurrency <N>                        Max concurrent HTTP POSTs [default: 10]
      --timeout-secs <SECS>                    HTTP request timeout [default: 10]
  -q, --quiet                                  Suppress status messages
  -h, --help                                   Print help
```

### `wshook http2ws`

```text
Usage: wshook http2ws [OPTIONS]

Options:
  -l, --listen <LISTEN>        Socket address to listen on [default: 127.0.0.1:8080]
      --http-path <PATH>       HTTP POST endpoint path [default: /webhook]
      --ws-path <PATH>         WebSocket endpoint path [default: /ws]
      --secret <SECRET>        Shared secret to validate X-Hub-Signature-256
      --buffer-size <N>        Number of recent payloads to buffer and replay [default: 0]
  -q, --quiet                  Suppress status messages
  -h, --help                   Print help
```

## Status

Fully functional and verified. Bi-directional WebSocket-to-HTTP and HTTP-to-WebSocket bridging, constant-time HMAC-SHA256 signing and verification, regex message filtering, JSON dot-path extraction, retry backoff, and buffer replay are implemented and covered by automated unit and integration tests.
