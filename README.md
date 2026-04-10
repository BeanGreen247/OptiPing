# OptiPing

<p align="center">
  <img src="icon.jpg" alt="OptiPing Logo" width="96"/>
</p>

A lightweight, self-hosted uptime monitor with a real-time status page. Inspired by the simplicity of [OpenStatus.dev](https://www.openstatus.dev), the dashboards of Uptime Kuma, and the latency focus of SmokePing.

- **Single Python process** — no Node.js, no Docker required
- **Under 100 MB RAM** in production
- **Async core** — monitors run concurrently via `asyncio`, non-blocking DB writes
- **Real-time UI** — Server-Sent Events push updates to the browser instantly
- **Zero build step** — Tailwind CSS and Chart.js loaded from CDN

---

## Quick Start

### 1. Clone / copy files

```
OptiPing/
├── uptime_monitor.py   # main entry point
├── core.py             # monitoring engine + database
├── server.py           # FastAPI web server + UI
├── config.toml         # configuration file
└── requirements.txt    # list of dependencies
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

> Requires **Python 3.10+**. On Debian/Ubuntu:
> ```bash
> sudo apt install python3 python3-pip
> pip install -r requirements.txt
> ```

### 3. Configure

Edit `config.toml` — at minimum define your monitors:

```toml
[[monitors]]
name = "Google DNS"
target = "8.8.8.8"

[[monitors]]
name = "My Web App"
target = "https://myapp.example.com"
```

### 4. Run

```bash
python uptime_monitor.py
```

Open **http://localhost:8080** in your browser.

![Status page showing monitor cards with green/red status dots and uptime percentages]

---

## Configuration Reference

### `[server]`

| Key | Default | Description |
|---|---|---|
| `host` | `0.0.0.0` | Bind address. Use `127.0.0.1` to restrict to localhost |
| `port` | `8080` | Status page port |
| `title` | `OptiPing Status` | Page title |
| `description` | `""` | Subtitle shown under title |

### `[auth]`

| Key | Default | Description |
|---|---|---|
| `enabled` | `false` | Enable HTTP Basic Auth on the status page |
| `username` | `admin` | Auth username |
| `password` | `changeme` | Auth password — **change this before exposing publicly** |
| `admin_password` | `changeme` | Password for `/admin` — **change this** |
| `totp_secret` | `""` | Base32 TOTP secret for admin 2FA — leave empty to disable |

#### Enabling 2FA for the admin panel

1. Generate a secret: `python3 -c "import pyotp; print(pyotp.random_base32())"`
2. Set `totp_secret = "<your-secret>"` in `config.toml`
3. Restart OptiPing
4. Open `/admin/2fa-setup` while logged in and scan the QR code with your authenticator app (Google Authenticator, Authy, etc.)

Once set, the login form will require both the admin password and the 6-digit code from your app.

### `[defaults]`

| Key | Default | Description |
|---|---|---|
| `interval` | `60` | Check interval in seconds |
| `timeout` | `5` | Connect/response timeout in seconds |
| `retries` | `3` | Retry attempts before marking DOWN |

### `[database]`

| Key | Default | Description |
|---|---|---|
| `path` | `optiping.db` | SQLite file location |
| `retention_days` | `30` | Days of check history to keep |

### `[logging]`

| Key | Default | Description |
|---|---|---|
| `level` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `file` | `optiping.log` | Log file path. Set to `""` to disable |
| `console` | `true` | Print logs to stdout |

---

## Monitor Types

The monitor type is auto-detected from the `target` string:

| Target format | Type | Example |
|---|---|---|
| Bare IP or hostname | ICMP ping | `8.8.8.8`, `router.local` |
| `host:port` | TCP connect | `google.com:443`, `192.168.1.10:22` |
| `http://…` or `https://…` | HTTP GET | `https://example.com/health` |

### Per-monitor overrides

Each monitor can override the global defaults:

```toml
[[monitors]]
name = "Slow API"
target = "https://legacy-api.internal/ping"
interval = 120    # check every 2 minutes
timeout = 15      # allow 15s for slow responses
retries = 2
```

---

## Alerting (Webhooks)

Add one or more `[[alerts]]` blocks to `config.toml`. Both Discord and Slack webhooks are supported with the same payload format.

### Discord

```toml
[[alerts]]
name = "Discord"
type = "webhook"
url = "https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN"
on_down = true
on_recovery = true
```

### Slack

```toml
[[alerts]]
name = "Slack"
type = "webhook"
url = "https://hooks.slack.com/services/T.../B.../..."
on_down = true
on_recovery = false   # only alert on outage, not recovery
```

Alerts fire **only on status change** (UP → DOWN or DOWN → UP), not on every check.

---

## CLI Options

```
python uptime_monitor.py --help

Options:
  -c, --config FILE   Path to config.toml (default: config.toml)
  -p, --port PORT     Override status page port from config
```

Examples:

```bash
# Use a custom config path
python uptime_monitor.py --config /etc/optiping/config.toml

# Override port without editing config
python uptime_monitor.py --port 9090

# Run in background (Linux)
nohup python uptime_monitor.py > /dev/null 2>&1 &
```

---

## API Endpoints

| Endpoint | Description |
|---|---|
| `GET /` | Status page (HTML) |
| `GET /health` | Health check — returns `{"status":"ok"}` |
| `GET /api/summary` | Overall up/down counts |
| `GET /api/monitors` | All monitors with uptime % and avg latency |
| `GET /api/monitors/{name}` | Full detail: timeline, recent checks, chart data |
| `GET /api/stream` | Server-Sent Events stream for real-time updates |

---

## Deploying to a Linux Server

The service file expects the project to live at `/opt/optiping`. Follow these steps on the server:

```bash
# 1. Create the install directory
sudo mkdir -p /opt/optiping

# 2a. Clone directly from GitHub (recommended)
sudo git clone https://github.com/BeanGreen247/OptiPing.git /opt/optiping

# 2b. Or copy local files
#   sudo cp -r /path/to/OptiPing/* /opt/optiping/

# 3. Install Python dependencies
cd /opt/optiping
sudo pip3 install -r requirements.txt

# 4. Edit the config — set a strong admin_password before exposing publicly
sudo nano /opt/optiping/config.toml
```

---

## Running as a systemd Service (Linux)

After deploying to `/opt/optiping`:

```bash
sudo cp /opt/optiping/optiping.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now optiping
sudo journalctl -u optiping -f    # follow logs
```

### Stopping the service

```bash
# Graceful stop (sends SIGTERM → waits → SIGKILL if needed)
sudo systemctl stop optiping

# Immediate force-kill (SIGKILL, no waiting)
sudo systemctl kill -s SIGKILL optiping

# Restart
sudo systemctl restart optiping
```

---

## Resource Usage

| Metric | Typical value |
|---|---|
| RAM | 30–60 MB (10 monitors) |
| CPU at idle | < 0.1% |
| CPU during checks | Spikes to ~1% per check batch |
| Disk (SQLite, 30d, 10 monitors) | ~5–15 MB |

---

## Project Structure

```
uptime_monitor.py   CLI entry point, config loading, asyncio orchestration
core.py             Database (SQLite), check logic (ping/tcp/http), scheduler, alerts
server.py           FastAPI app, REST API, SSE stream, HTML status page template
config.toml         User configuration
optiping.service    Example systemd service file
requirements.txt    Python dependencies (7 packages)
optiping.db         SQLite database (created on first run)
optiping.log        Log file (created on first run)
```

---

## Dependencies

| Package | Version | Purpose |
|---|---|---|
| `fastapi` | 0.115 | Async web framework |
| `uvicorn[standard]` | 0.34 | ASGI server |
| `aiohttp` | 3.11 | Async HTTP client for HTTP monitor checks |
| `ping3` | 4.0 | ICMP ping (no subprocess) |
| `toml` | 0.10 | Config file parser |
| `python-socketio` | 5.12 | WebSocket/SSE support |
| `python-multipart` | 0.0.20 | FastAPI form support (optional auth) |

`sqlite3` is Python stdlib — no install needed.

---

## Tested Configuration (Localhost)

```toml
[[monitors]]
name = "Google DNS"
target = "8.8.8.8"
interval = 30

[[monitors]]
name = "Google TCP"
target = "google.com:443"
interval = 60

[[monitors]]
name = "Google HTTPS"
target = "https://www.google.com"
interval = 60
```

Run: `python uptime_monitor.py` → open http://localhost:8080

---

## Troubleshooting

**Ping checks fail / permission denied**
ICMP requires raw socket privileges on Linux:
```bash
sudo python uptime_monitor.py
# or grant capability to python binary:
sudo setcap cap_net_raw+ep $(which python3)
```

**Port 8080 already in use**
```bash
python uptime_monitor.py --port 8181
```

**No data showing in UI**
Monitors need at least one completed check cycle. Check logs:
```bash
tail -f optiping.log
```
