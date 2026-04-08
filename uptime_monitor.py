# Copyright (c) 2026 Tomáš Moždřeň (BeanGreen247)
# https://github.com/BeanGreen247/OptiPing
# MIT License

from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys
from pathlib import Path

import toml
import uvicorn

from core import Database, MonitorConfig, MonitorScheduler
from server import create_app

def setup_logging(level: str, log_file: str, console: bool):
    handlers: list[logging.Handler] = []

    if console:
        h = logging.StreamHandler(sys.stdout)
        h.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-8s %(name)s  %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        handlers.append(h)

    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-8s %(name)s  %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        handlers.append(fh)

    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        handlers=handlers,
        force=True,
    )
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.error").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)


log = logging.getLogger("optiping")


_DEFAULTS = {
    "server": {"host": "0.0.0.0", "port": 8080, "title": "OptiPing Status", "description": ""},
    "auth": {"enabled": False, "username": "admin", "password": "changeme", "admin_password": "changeme"},
    "defaults": {"interval": 60, "timeout": 5, "retries": 3},
    "database": {"path": "optiping.db", "retention_days": 30},
    "logging": {"level": "INFO", "file": "optiping.log", "console": True},
}


def _deep_merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(result.get(k), dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


def load_config(path: str) -> dict:
    cfg_path = Path(path)
    if not cfg_path.exists():
        log.warning(f"config not found at {path!r}, using built-in defaults")
        return dict(_DEFAULTS)

    try:
        raw = toml.loads(cfg_path.read_text(encoding="utf-8"))
    except Exception as exc:
        log.error(f"failed to parse config {path!r}: {exc}")
        sys.exit(1)

    cfg = _deep_merge(_DEFAULTS, raw)

    if not cfg.get("monitors"):
        log.error("no [[monitors]] defined in config — add at least one monitor")
        sys.exit(1)

    return cfg


def build_monitors(cfg: dict) -> list[MonitorConfig]:
    defaults = cfg.get("defaults", {})
    monitors = []
    for raw in cfg.get("monitors", []):
        if not isinstance(raw, dict):
            log.warning(f"skipping invalid monitor entry: {raw!r}")
            continue
        name = raw.get("name", "").strip()
        target = raw.get("target", "").strip()
        if not name or not target:
            log.warning(f"monitor missing name or target, skipping: {raw!r}")
            continue
        monitors.append(MonitorConfig(
            name=name,
            target=target,
            interval=int(raw.get("interval", defaults.get("interval", 60))),
            timeout=int(raw.get("timeout", defaults.get("timeout", 5))),
            retries=int(raw.get("retries", defaults.get("retries", 3))),
        ))
    return monitors


async def run(config_path: str, port_override: int | None):
    cfg = load_config(config_path)

    log_cfg = cfg.get("logging", {})
    setup_logging(
        level=log_cfg.get("level", "INFO"),
        log_file=log_cfg.get("file", ""),
        console=log_cfg.get("console", True),
    )

    log.info("OptiPing starting up")

    server_cfg = cfg.get("server", {})
    host = server_cfg.get("host", "0.0.0.0")
    port = port_override or int(server_cfg.get("port", 8080))

    db_cfg = cfg.get("database", {})
    db = Database(db_cfg.get("path", "optiping.db"))
    db.connect()

    alert_configs = cfg.get("alerts", [])
    scheduler = MonitorScheduler(db, alert_configs)

    monitors = build_monitors(cfg)
    if not monitors:
        log.error("no valid monitors loaded — check your config")
        db.close()
        sys.exit(1)

    for m in monitors:
        scheduler.add_monitor(m)
        log.info(f"  monitor registered: {m.name!r} ({m.kind}) -> {m.target!r}")

    app = create_app(db, scheduler, cfg)

    # --- uvicorn server (non-blocking) ---
    uv_config = uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level="warning",
        access_log=False,
        loop="asyncio",
    )
    server = uvicorn.Server(uv_config)

    stop_event = asyncio.Event()

    def _handle_signal():
        log.info("shutdown signal received")
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _handle_signal)
        except (NotImplementedError, RuntimeError):
            signal.signal(sig, lambda s, f: stop_event.set())

    await scheduler.start()
    prune_task = asyncio.create_task(
        scheduler.prune_loop(db_cfg.get("retention_days", 30)),
        name="prune_loop",
    )

    log.info(f"status page:  http://{host if host != '0.0.0.0' else 'localhost'}:{port}/")
    log.info(f"health check: http://{host if host != '0.0.0.0' else 'localhost'}:{port}/health")
    log.info(f"loaded {len(monitors)} monitor(s) — press Ctrl+C to stop")

    serve_task = asyncio.create_task(server.serve(), name="uvicorn")
    stop_task  = asyncio.create_task(stop_event.wait(), name="stop_signal")

    done, pending = await asyncio.wait(
        [serve_task, stop_task],
        return_when=asyncio.FIRST_COMPLETED,
    )

    server.should_exit = True

    for t in pending:
        t.cancel()
        try:
            await t
        except (asyncio.CancelledError, Exception):
            pass

    prune_task.cancel()
    try:
        await prune_task
    except asyncio.CancelledError:
        pass

    await scheduler.stop()
    db.close()
    log.info("OptiPing stopped cleanly")


def main():
    parser = argparse.ArgumentParser(
        prog="optiping",
        description="OptiPing — lightweight uptime monitor with status page",
    )
    parser.add_argument(
        "--config", "-c",
        default="config.toml",
        metavar="FILE",
        help="path to config.toml (default: config.toml)",
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=None,
        metavar="PORT",
        help="override status page port from config",
    )
    args = parser.parse_args()

    try:
        asyncio.run(run(args.config, args.port))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
