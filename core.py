# Copyright (c) 2026 Tomáš Moždřeň (BeanGreen247)
# https://github.com/BeanGreen247/OptiPing
# MIT License

from __future__ import annotations

import asyncio
import logging
import re
import socket
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import aiohttp
import sqlite3

log = logging.getLogger("optiping.core")

# Data models

@dataclass
class MonitorConfig:
    name: str
    target: str
    interval: int = 60
    timeout: int = 5
    retries: int = 3

    kind: str = ""
    host: str = ""
    port: int = 0
    url: str = ""

    def __post_init__(self):
        self.kind, self.host, self.port, self.url = _parse_target(self.target)


@dataclass
class CheckResult:
    monitor_name: str
    status: str
    response_ms: Optional[float]
    checked_at: float = field(default_factory=time.time)
    error: str = ""


@dataclass
class MonitorState:
    config: MonitorConfig
    current_status: str = "unknown"
    last_check: Optional[float] = None
    last_response_ms: Optional[float] = None


_HTTP_RE = re.compile(r"^https?://", re.IGNORECASE)
_HOST_PORT_RE = re.compile(r"^(.+):(\d+)$")


def _parse_target(target: str) -> tuple[str, str, int, str]:
    t = target.strip()

    if _HTTP_RE.match(t):
        parsed = urlparse(t)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return "http", host, port, t

    m = _HOST_PORT_RE.match(t)
    if m:
        host, port_str = m.group(1), m.group(2)
        return "tcp", host, int(port_str), ""

    return "ping", t, 0, ""


_CREATE_MONITORS = """
CREATE TABLE IF NOT EXISTS monitors (
    id          INTEGER PRIMARY KEY,
    name        TEXT    UNIQUE NOT NULL,
    target      TEXT    NOT NULL,
    kind        TEXT    NOT NULL,
    created_at  REAL    NOT NULL DEFAULT (unixepoch())
);
"""

_CREATE_CHECKS = """
CREATE TABLE IF NOT EXISTS checks (
    id           INTEGER PRIMARY KEY,
    monitor_name TEXT    NOT NULL,
    status       TEXT    NOT NULL,
    response_ms  REAL,
    error        TEXT    DEFAULT '',
    checked_at   REAL    NOT NULL
);
"""

_CREATE_IDX = """
CREATE INDEX IF NOT EXISTS idx_checks_monitor_time
    ON checks (monitor_name, checked_at DESC);
"""

_CREATE_INCIDENTS = """
CREATE TABLE IF NOT EXISTS incidents (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    title       TEXT    NOT NULL,
    body        TEXT    DEFAULT '',
    severity    TEXT    NOT NULL DEFAULT 'investigating',
    created_at  REAL    NOT NULL,
    updated_at  REAL    NOT NULL,
    resolved_at REAL
);
"""


class Database:
    def __init__(self, path: str):
        self._path = path
        self._conn: Optional[sqlite3.Connection] = None
        self._lock = asyncio.Lock()

    def connect(self):
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._conn.execute(_CREATE_MONITORS)
        self._conn.execute(_CREATE_CHECKS)
        self._conn.execute(_CREATE_IDX)
        self._conn.execute(_CREATE_INCIDENTS)
        self._conn.commit()
        log.info(f"database opened: {self._path}")

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

    async def save_check(self, result: CheckResult):
        async with self._lock:
            self._conn.execute(
                "INSERT INTO checks (monitor_name, status, response_ms, error, checked_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (result.monitor_name, result.status, result.response_ms,
                 result.error, result.checked_at),
            )
            self._conn.commit()

    async def upsert_monitor(self, cfg: MonitorConfig):
        async with self._lock:
            self._conn.execute(
                "INSERT INTO monitors (name, target, kind) VALUES (?, ?, ?)"
                " ON CONFLICT(name) DO UPDATE SET target=excluded.target, kind=excluded.kind",
                (cfg.name, cfg.target, cfg.kind),
            )
            self._conn.commit()

    async def prune(self, retention_days: int):
        cutoff = time.time() - retention_days * 86400
        async with self._lock:
            self._conn.execute(
                "DELETE FROM checks WHERE checked_at < ?", (cutoff,)
            )
            self._conn.commit()
        log.debug(f"pruned checks older than {retention_days}d")

    def get_recent_checks(self, monitor_name: str, limit: int = 100) -> list[dict]:
        cur = self._conn.execute(
            "SELECT status, response_ms, error, checked_at FROM checks"
            " WHERE monitor_name = ? ORDER BY checked_at DESC LIMIT ?",
            (monitor_name, limit),
        )
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def get_uptime_pct(self, monitor_name: str, hours: int = 24) -> float:
        since = time.time() - hours * 3600
        cur = self._conn.execute(
            "SELECT COUNT(*) as total,"
            " SUM(CASE WHEN status='up' THEN 1 ELSE 0 END) as up_count"
            " FROM checks WHERE monitor_name = ? AND checked_at >= ?",
            (monitor_name, since),
        )
        row = cur.fetchone()
        total, up_count = row[0], row[1] or 0
        return round((up_count / total * 100), 2) if total else 0.0

    def get_avg_latency(self, monitor_name: str, hours: int = 24) -> Optional[float]:
        since = time.time() - hours * 3600
        cur = self._conn.execute(
            "SELECT AVG(response_ms) FROM checks"
            " WHERE monitor_name = ? AND checked_at >= ? AND status = 'up'",
            (monitor_name, since),
        )
        val = cur.fetchone()[0]
        return round(val, 2) if val is not None else None

    def get_timeline(self, monitor_name: str, hours: int = 24, buckets: int = 48) -> list[dict]:
        since = time.time() - hours * 3600
        bucket_size = (hours * 3600) / buckets
        cur = self._conn.execute(
            "SELECT checked_at, status, response_ms FROM checks"
            " WHERE monitor_name = ? AND checked_at >= ?"
            " ORDER BY checked_at ASC",
            (monitor_name, since),
        )
        rows = cur.fetchall()

        result = []
        for i in range(buckets):
            bucket_start = since + i * bucket_size
            bucket_end = bucket_start + bucket_size
            in_bucket = [r for r in rows if bucket_start <= r[0] < bucket_end]
            if not in_bucket:
                result.append({"t": bucket_start, "status": "no_data", "avg_ms": None})
                continue
            up = sum(1 for r in in_bucket if r[1] == "up")
            avg_ms = (
                sum(r[2] for r in in_bucket if r[2] is not None) / len(in_bucket)
                if any(r[2] is not None for r in in_bucket)
                else None
            )
            result.append({
                "t": bucket_start,
                "status": "up" if up == len(in_bucket) else ("degraded" if up > 0 else "down"),
                "avg_ms": round(avg_ms, 2) if avg_ms is not None else None,
            })
        return result

    def get_all_monitor_names(self) -> list[str]:
        cur = self._conn.execute("SELECT name FROM monitors ORDER BY name")
        return [row[0] for row in cur.fetchall()]

    async def create_incident(self, title: str, body: str, severity: str) -> int:
        now = time.time()
        async with self._lock:
            cur = self._conn.execute(
                "INSERT INTO incidents (title, body, severity, created_at, updated_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (title, body, severity, now, now),
            )
            self._conn.commit()
            return cur.lastrowid

    async def update_incident(self, incident_id: int, body: str, severity: str):
        now = time.time()
        async with self._lock:
            self._conn.execute(
                "UPDATE incidents SET body=?, severity=?, updated_at=? WHERE id=?",
                (body, severity, now, incident_id),
            )
            self._conn.commit()

    async def resolve_incident(self, incident_id: int):
        now = time.time()
        async with self._lock:
            self._conn.execute(
                "UPDATE incidents SET severity='resolved', resolved_at=?, updated_at=? WHERE id=?",
                (now, now, incident_id),
            )
            self._conn.commit()

    async def delete_incident(self, incident_id: int):
        async with self._lock:
            self._conn.execute("DELETE FROM incidents WHERE id=?", (incident_id,))
            self._conn.commit()

    def get_incidents(self, include_resolved: bool = False, limit: int = 20) -> list[dict]:
        if include_resolved:
            cur = self._conn.execute(
                "SELECT id, title, body, severity, created_at, updated_at, resolved_at"
                " FROM incidents ORDER BY created_at DESC LIMIT ?",
                (limit,),
            )
        else:
            cur = self._conn.execute(
                "SELECT id, title, body, severity, created_at, updated_at, resolved_at"
                " FROM incidents WHERE resolved_at IS NULL ORDER BY created_at DESC LIMIT ?",
                (limit,),
            )
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]


async def _check_ping(host: str, timeout: int) -> tuple[str, Optional[float]]:
    try:
        import ping3
        ping3.EXCEPTIONS = True
        start = time.perf_counter()
        delay = await asyncio.get_event_loop().run_in_executor(
            None, lambda: ping3.ping(host, timeout=timeout, unit="ms")
        )
        if delay is None:
            return "down", None
        elapsed = (time.perf_counter() - start) * 1000
        return "up", round(elapsed, 2)
    except Exception as exc:
        log.debug(f"ping {host} failed: {exc}")
        return "down", None


async def _check_tcp(host: str, port: int, timeout: int) -> tuple[str, Optional[float]]:
    start = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        elapsed = (time.perf_counter() - start) * 1000
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return "up", round(elapsed, 2)
    except (asyncio.TimeoutError, OSError, ConnectionRefusedError) as exc:
        log.debug(f"tcp {host}:{port} failed: {exc}")
        return "down", None


async def _check_http(
    url: str, timeout: int, session: aiohttp.ClientSession
) -> tuple[str, Optional[float]]:
    start = time.perf_counter()
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=True,
            ssl=False,
        ) as resp:
            elapsed = (time.perf_counter() - start) * 1000
            if 200 <= resp.status <= 299:
                return "up", round(elapsed, 2)
            return "down", round(elapsed, 2)
    except Exception as exc:
        log.debug(f"http {url} failed: {exc}")
        return "down", None


async def run_check(
    cfg: MonitorConfig,
    session: aiohttp.ClientSession,
) -> CheckResult:
    last_status = "down"
    last_ms: Optional[float] = None
    last_err = ""

    for attempt in range(1, cfg.retries + 1):
        try:
            if cfg.kind == "ping":
                status, ms = await _check_ping(cfg.host, cfg.timeout)
            elif cfg.kind == "tcp":
                status, ms = await _check_tcp(cfg.host, cfg.port, cfg.timeout)
            else:
                status, ms = await _check_http(cfg.url, cfg.timeout, session)

            last_status = status
            last_ms = ms
            last_err = ""

            if status == "up":
                break

            if attempt < cfg.retries:
                await asyncio.sleep(1)

        except Exception as exc:
            last_err = str(exc)
            log.warning(f"check error [{cfg.name}] attempt {attempt}: {exc}")
            if attempt < cfg.retries:
                await asyncio.sleep(1)

    return CheckResult(
        monitor_name=cfg.name,
        status=last_status,
        response_ms=last_ms,
        error=last_err,
    )


async def send_webhook_alert(
    url: str,
    monitor_name: str,
    new_status: str,
    prev_status: str,
    response_ms: Optional[float],
    session: aiohttp.ClientSession,
):
    color = 0xFF0000 if new_status == "down" else 0x00FF00
    emoji = "🔴" if new_status == "down" else "🟢"
    title = f"{emoji} {monitor_name} is {new_status.upper()}"
    description = (
        f"**Monitor**: {monitor_name}\n"
        f"**Status**: {new_status.upper()}\n"
        f"**Previous**: {prev_status.upper()}\n"
        f"**Latency**: {f'{response_ms:.1f}ms' if response_ms else 'N/A'}"
    )

    # Discord-compatible payload (also works with Slack incoming webhooks via text field)
    payload = {
        "embeds": [{
            "title": title,
            "description": description,
            "color": color,
        }],
        "text": f"{title}\n{description}",
    }

    try:
        async with session.post(
            url,
            json=payload,
            timeout=aiohttp.ClientTimeout(total=10),
        ) as resp:
            if resp.status not in (200, 204):
                body = await resp.text()
                log.warning(f"webhook returned {resp.status}: {body[:200]}")
    except Exception as exc:
        log.warning(f"webhook send failed: {exc}")


class MonitorScheduler:
    def __init__(self, db: Database, alert_configs: list[dict]):
        self._db = db
        self._alert_configs = alert_configs
        self._states: dict[str, MonitorState] = {}
        self._tasks: list[asyncio.Task] = []
        self._session: Optional[aiohttp.ClientSession] = None
        self._event_subscribers: list[asyncio.Queue] = []
        self._running = False

    def add_monitor(self, cfg: MonitorConfig):
        self._states[cfg.name] = MonitorState(config=cfg)

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=256)
        self._event_subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue):
        if q in self._event_subscribers:
            self._event_subscribers.remove(q)

    def get_states(self) -> dict[str, dict]:
        result = {}
        for name, state in self._states.items():
            result[name] = {
                "name": name,
                "target": state.config.target,
                "kind": state.config.kind,
                "status": state.current_status,
                "last_check": state.last_check,
                "last_response_ms": state.last_response_ms,
            }
        return result

    async def _publish(self, result: CheckResult):
        payload = {
            "monitor_name": result.monitor_name,
            "status": result.status,
            "response_ms": result.response_ms,
            "checked_at": result.checked_at,
        }
        for q in list(self._event_subscribers):
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                pass

    async def _alert_if_changed(
        self, name: str, new_status: str, prev_status: str, ms: Optional[float]
    ):
        if new_status == prev_status or prev_status == "unknown":
            return
        for alert in self._alert_configs:
            if not alert.get("url"):
                continue
            if new_status == "down" and not alert.get("on_down", True):
                continue
            if new_status == "up" and not alert.get("on_recovery", True):
                continue
            await send_webhook_alert(
                alert["url"], name, new_status, prev_status, ms, self._session
            )

    async def _monitor_loop(self, state: MonitorState):
        cfg = state.config
        log.info(f"starting monitor: {cfg.name} ({cfg.kind}) every {cfg.interval}s")

        while self._running:
            result = await run_check(cfg, self._session)

            prev = state.current_status
            state.current_status = result.status
            state.last_check = result.checked_at
            state.last_response_ms = result.response_ms

            await self._db.save_check(result)
            await self._publish(result)
            await self._alert_if_changed(cfg.name, result.status, prev, result.response_ms)

            log_fn = log.info if result.status == "up" else log.warning
            ms_str = f"{result.response_ms:.1f}ms" if result.response_ms is not None else "timeout"
            log_fn(f"[{cfg.name}] {result.status.upper()} {ms_str}")

            await asyncio.sleep(cfg.interval)

    async def start(self):
        self._running = True
        connector = aiohttp.TCPConnector(limit=50, ttl_dns_cache=300)
        self._session = aiohttp.ClientSession(
            connector=connector,
            headers={"User-Agent": "OptiPing/1.0"},
        )

        for name, state in self._states.items():
            await self._db.upsert_monitor(state.config)
            task = asyncio.create_task(
                self._monitor_loop(state), name=f"monitor:{name}"
            )
            self._tasks.append(task)

        log.info(f"scheduler started with {len(self._tasks)} monitors")

    async def stop(self):
        self._running = False
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        if self._session:
            await self._session.close()
        log.info("scheduler stopped")

    async def prune_loop(self, retention_days: int):
        while self._running:
            await asyncio.sleep(3600)
            await self._db.prune(retention_days)
