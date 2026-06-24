"""
Thread-safe in-memory stats tracker shared between the bot and the dashboard.
"""
import threading
import time
from collections import deque

_lock = threading.Lock()

_data = {
    "start_time": time.time(),
    "total_users": set(),
    "total_checks": 0,
    "total_hits": 0,
    "total_invalids": 0,
    "total_frees": 0,
    "total_errors": 0,
    "total_on_hold": 0,
    # Rolling window for checks/min (timestamps of recent checks)
    "recent_checks": deque(maxlen=500),
    # Last 20 activity events
    "activity": deque(maxlen=20),
}


def record_user(user_id: int) -> None:
    with _lock:
        _data["total_users"].add(user_id)


def record_check(status: str, user_id: int = 0, source: str = "") -> None:
    with _lock:
        _data["total_checks"] += 1
        _data["recent_checks"].append(time.time())
        if status == "hit":
            _data["total_hits"] += 1
        elif status == "invalid":
            _data["total_invalids"] += 1
        elif status == "free":
            _data["total_frees"] += 1
        elif status == "on_hold":
            _data["total_on_hold"] += 1
        else:
            _data["total_errors"] += 1
        _data["activity"].appendleft({
            "time": time.strftime("%H:%M:%S"),
            "status": status,
            "source": source or "unknown",
        })


def get_stats() -> dict:
    with _lock:
        now = time.time()
        uptime_secs = int(now - _data["start_time"])
        h, rem = divmod(uptime_secs, 3600)
        m, s = divmod(rem, 60)
        uptime_str = f"{h}h {m}m {s}s"

        # Checks in last 60 seconds
        window = [t for t in _data["recent_checks"] if now - t <= 60]
        checks_per_min = len(window)

        total = _data["total_checks"]
        hits = _data["total_hits"]
        hit_rate = round(hits / total * 100, 1) if total else 0

        return {
            "uptime": uptime_str,
            "total_users": len(_data["total_users"]),
            "total_checks": total,
            "total_hits": hits,
            "total_invalids": _data["total_invalids"],
            "total_frees": _data["total_frees"],
            "total_on_hold": _data["total_on_hold"],
            "total_errors": _data["total_errors"],
            "checks_per_min": checks_per_min,
            "hit_rate": hit_rate,
            "activity": list(_data["activity"]),
        }
