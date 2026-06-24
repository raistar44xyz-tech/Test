"""
Proxy Manager — Admin-controlled proxy pool.
State persisted in SQLite (proxy_pool.db).
Default: OFF (direct connection).

Features:
  - Any common proxy format (auto-normalized on add)
  - Source URLs stored; auto-refreshed every 60 seconds in background
  - Dead proxy auto-removal: socket health-check removes unreachable proxies
  - Failure tracking: 3 consecutive failures → permanent removal
  - No proxies hardcoded; admin adds source URLs manually
"""

import re
import socket
import sqlite3
import threading
import time
import logging
import requests
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_DB_FILE = Path("proxy_pool.db")
_AUTO_REFRESH_INTERVAL = 60        # seconds between source re-fetches
_HEALTH_CHECK_INTERVAL = 120       # seconds between full pool health checks
_MAX_FAILURES = 3                  # consecutive failures before permanent removal
_SOCKET_TIMEOUT = 5                # seconds for socket health-check
_FETCH_TIMEOUT = 20                # seconds for HTTP source fetch


# ---------------------------------------------------------------------------
# Format normalizer
# ---------------------------------------------------------------------------

def normalize_proxy_url(raw: str) -> str | None:
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return None
    if "://" in raw:
        if raw.startswith(("http://", "https://", "socks5://", "socks4://")):
            return raw
        return None
    if "@" in raw:
        return "http://" + raw
    parts = raw.split(":")
    if len(parts) == 2:
        host, port = parts
        if port.isdigit() and 1 <= int(port) <= 65535:
            return f"http://{host}:{port}"
    elif len(parts) == 4:
        if parts[1].isdigit() and 1 <= int(parts[1]) <= 65535:
            host, port, user, pwd = parts
            return f"http://{user}:{pwd}@{host}:{port}"
        elif parts[3].isdigit() and 1 <= int(parts[3]) <= 65535:
            user, pwd, host, port = parts
            return f"http://{user}:{pwd}@{host}:{port}"
    return None


def _parse_host_port(proxy_url: str) -> tuple[str, int] | None:
    """Extract (host, port) from a proxy URL for socket health-check."""
    try:
        parsed = urlparse(proxy_url)
        host = parsed.hostname
        port = parsed.port
        if host and port:
            return host, port
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(_DB_FILE), check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def _init_db() -> None:
    with _get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS proxies (
                url       TEXT PRIMARY KEY,
                added_at  REAL NOT NULL DEFAULT 0,
                fail_count INTEGER NOT NULL DEFAULT 0,
                last_fail  REAL NOT NULL DEFAULT 0,
                last_ok    REAL NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS sources (
                url      TEXT PRIMARY KEY,
                added_at REAL NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS config (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL DEFAULT ''
            );
        """)
        conn.execute(
            "INSERT OR IGNORE INTO config (key, value) VALUES ('enabled', '0')"
        )


# ---------------------------------------------------------------------------
# Socket-based health check (no HTTP through proxy — avoids any web bans)
# ---------------------------------------------------------------------------

def _is_proxy_alive(proxy_url: str, timeout: float = _SOCKET_TIMEOUT) -> bool:
    """
    Check if the proxy server is reachable by attempting a TCP connection.
    Does NOT make any HTTP request through the proxy.
    """
    hp = _parse_host_port(proxy_url)
    if not hp:
        return False
    host, port = hp
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


# ---------------------------------------------------------------------------
# ProxyManager
# ---------------------------------------------------------------------------

class ProxyManager:
    def __init__(self):
        _init_db()
        self._lock = threading.Lock()
        self._idx: int = 0
        self._stop_event = threading.Event()
        self._bg_thread = threading.Thread(
            target=self._background_loop, daemon=True, name="proxy-bg"
        )
        self._bg_thread.start()

    # ── Background thread ─────────────────────────────────────────────────

    def _background_loop(self) -> None:
        last_refresh = 0.0
        last_health = 0.0
        while not self._stop_event.is_set():
            now = time.time()
            try:
                if now - last_refresh >= _AUTO_REFRESH_INTERVAL:
                    self._auto_refresh_sources()
                    last_refresh = now
                if now - last_health >= _HEALTH_CHECK_INTERVAL:
                    self._health_check_all()
                    last_health = now
            except Exception as exc:
                logger.warning(f"proxy_manager: background error: {exc}")
            self._stop_event.wait(timeout=10)

    def _auto_refresh_sources(self) -> None:
        sources = self.list_sources()
        if not sources:
            return
        added = 0
        for url in sources:
            a, _, _ = self.fetch_from_url(url)
            added += a
        if added:
            logger.info(f"proxy_manager: auto-refresh added {added} proxies")

    def _health_check_all(self) -> None:
        """Socket-check every proxy; permanently remove dead ones."""
        with _get_conn() as conn:
            rows = conn.execute("SELECT url FROM proxies").fetchall()
        urls = [r[0] for r in rows]
        if not urls:
            return
        removed = 0
        for url in urls:
            alive = _is_proxy_alive(url)
            if alive:
                with _get_conn() as conn:
                    conn.execute(
                        "UPDATE proxies SET fail_count=0, last_ok=? WHERE url=?",
                        (time.time(), url),
                    )
            else:
                self._increment_failure(url, force_remove=True)
                removed += 1
        if removed:
            logger.info(f"proxy_manager: health-check removed {removed} dead proxies")

    # ── Persistence helpers ───────────────────────────────────────────────

    def _increment_failure(self, url: str, force_remove: bool = False) -> None:
        with _get_conn() as conn:
            conn.execute(
                "UPDATE proxies SET fail_count = fail_count + 1, last_fail = ? WHERE url = ?",
                (time.time(), url),
            )
            row = conn.execute(
                "SELECT fail_count FROM proxies WHERE url = ?", (url,)
            ).fetchone()
        if row and (row[0] >= _MAX_FAILURES or force_remove):
            self._permanently_remove(url)

    def _permanently_remove(self, url: str) -> None:
        with _get_conn() as conn:
            conn.execute("DELETE FROM proxies WHERE url = ?", (url,))
        logger.info(f"proxy_manager: removed dead proxy {url[:40]}…")

    # ── Properties ───────────────────────────────────────────────────────

    @property
    def count(self) -> int:
        with _get_conn() as conn:
            row = conn.execute("SELECT COUNT(*) FROM proxies").fetchone()
        return row[0] if row else 0

    @property
    def available_count(self) -> int:
        return self.count

    @property
    def enabled(self) -> bool:
        with _get_conn() as conn:
            row = conn.execute(
                "SELECT value FROM config WHERE key='enabled'"
            ).fetchone()
        return bool(int(row[0])) if row else False

    # ── Toggle ───────────────────────────────────────────────────────────

    def toggle(self) -> bool:
        new_val = not self.enabled
        with _get_conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO config (key, value) VALUES ('enabled', ?)",
                ("1" if new_val else "0",),
            )
        return new_val

    def set_enabled(self, val: bool) -> None:
        with _get_conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO config (key, value) VALUES ('enabled', ?)",
                ("1" if val else "0",),
            )

    # ── Add / remove individual proxies ──────────────────────────────────

    def add_proxy_raw(self, raw: str) -> tuple[bool, str]:
        normalized = normalize_proxy_url(raw)
        if not normalized:
            return False, (
                "Could not parse that as a proxy. Accepted formats:\n"
                "  • <code>host:port</code>\n"
                "  • <code>host:port:user:pass</code>\n"
                "  • <code>user:pass@host:port</code>\n"
                "  • <code>http://user:pass@host:port</code>\n"
                "  • <code>socks5://host:port</code>"
            )
        with _get_conn() as conn:
            existing = conn.execute(
                "SELECT url FROM proxies WHERE url=?", (normalized,)
            ).fetchone()
            if existing:
                return False, f"Already in list: <code>{normalized}</code>"
            conn.execute(
                "INSERT INTO proxies (url, added_at) VALUES (?, ?)",
                (normalized, time.time()),
            )
        return True, normalized

    def remove_proxy(self, index: int) -> str | None:
        with _get_conn() as conn:
            rows = conn.execute(
                "SELECT url FROM proxies ORDER BY added_at ASC"
            ).fetchall()
        if 0 <= index < len(rows):
            url = rows[index][0]
            with _get_conn() as conn:
                conn.execute("DELETE FROM proxies WHERE url=?", (url,))
            return url
        return None

    def clear_proxies(self) -> int:
        with _get_conn() as conn:
            count = conn.execute("SELECT COUNT(*) FROM proxies").fetchone()[0]
            conn.execute("DELETE FROM proxies")
        return count

    def list_proxies(self) -> list[str]:
        with _get_conn() as conn:
            rows = conn.execute(
                "SELECT url FROM proxies ORDER BY added_at ASC"
            ).fetchall()
        return [r[0] for r in rows]

    def proxies_as_text(self) -> str:
        """Return all proxies as a plain-text string (one per line)."""
        return "\n".join(self.list_proxies())

    # ── Source URLs ───────────────────────────────────────────────────────

    def add_source(self, url: str) -> tuple[bool, str]:
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            return False, "Source URL must start with http:// or https://"
        with _get_conn() as conn:
            existing = conn.execute(
                "SELECT url FROM sources WHERE url=?", (url,)
            ).fetchone()
            if existing:
                return False, "Source URL already saved."
            conn.execute(
                "INSERT INTO sources (url, added_at) VALUES (?, ?)",
                (url, time.time()),
            )
        return True, url

    def remove_source(self, index: int) -> str | None:
        with _get_conn() as conn:
            rows = conn.execute(
                "SELECT url FROM sources ORDER BY added_at ASC"
            ).fetchall()
        if 0 <= index < len(rows):
            url = rows[index][0]
            with _get_conn() as conn:
                conn.execute("DELETE FROM sources WHERE url=?", (url,))
            return url
        return None

    def list_sources(self) -> list[str]:
        with _get_conn() as conn:
            rows = conn.execute(
                "SELECT url FROM sources ORDER BY added_at ASC"
            ).fetchall()
        return [r[0] for r in rows]

    def fetch_from_url(self, url: str) -> tuple[int, int, str]:
        """
        Fetch a plain-text proxy list from url and add new entries.
        Returns (added, skipped, error_msg).
        """
        try:
            resp = requests.get(url, timeout=_FETCH_TIMEOUT, headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/124.0.0.0 Safari/537.36"
                )
            })
            resp.raise_for_status()
            text = resp.text
        except Exception as e:
            return 0, 0, str(e)

        added = 0
        skipped = 0
        now = time.time()
        with _get_conn() as conn:
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    skipped += 1
                    continue
                normalized = normalize_proxy_url(line)
                if not normalized:
                    skipped += 1
                    continue
                existing = conn.execute(
                    "SELECT url FROM proxies WHERE url=?", (normalized,)
                ).fetchone()
                if existing:
                    skipped += 1
                else:
                    conn.execute(
                        "INSERT INTO proxies (url, added_at) VALUES (?, ?)",
                        (normalized, now),
                    )
                    added += 1
        return added, skipped, ""

    def refresh_all_sources(self) -> tuple[int, int, list[str]]:
        """Re-fetch all saved source URLs. Returns (total_added, total_skipped, errors)."""
        sources = self.list_sources()
        total_added = 0
        total_skipped = 0
        errors = []
        for url in sources:
            added, skipped, err = self.fetch_from_url(url)
            total_added += added
            total_skipped += skipped
            if err:
                errors.append(f"{url[:40]}… → {err}")
        return total_added, total_skipped, errors

    # ── Runtime helpers (used by checker.py) ─────────────────────────────

    def get_proxies_dict(self) -> dict | None:
        if not self.enabled:
            return None
        with _get_conn() as conn:
            rows = conn.execute(
                "SELECT url FROM proxies ORDER BY last_ok DESC, added_at ASC"
            ).fetchall()
        available = [r[0] for r in rows]
        if not available:
            return None
        with self._lock:
            self._idx = (self._idx + 1) % len(available)
            url = available[self._idx]
        return {"http": url, "https": url}

    def mark_failure(self, url: str) -> None:
        """Called by checker.py when a request through this proxy fails."""
        if url:
            self._increment_failure(url)

    # ── Display ──────────────────────────────────────────────────────────

    def status_text(self) -> str:
        with _get_conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM proxies").fetchone()[0]
            src_count = conn.execute("SELECT COUNT(*) FROM sources").fetchone()[0]
        src_note = f" · {src_count} source{'s' if src_count != 1 else ''}" if src_count else ""
        if not self.enabled:
            if total == 0:
                return f"🔴 <b>OFF</b> — direct connection  (no proxies stored{src_note})"
            return f"🔴 <b>OFF</b> — direct connection  ({total} proxies stored{src_note})"
        if total == 0:
            return f"🟡 <b>ON</b> — no proxies yet, falling back to direct{src_note}"
        return f"🟢 <b>ON</b> — {total} proxies available{src_note}"


proxy_manager = ProxyManager()
