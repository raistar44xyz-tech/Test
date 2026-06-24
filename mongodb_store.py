"""
Optional MongoDB persistence for Netflix cookie checker hits.
Activated only when MONGODB_URL environment variable is set.
If pymongo is not installed or MONGODB_URL is not set, all calls are no-ops.

Handles transient connection drops by attempting a lazy reconnect on the
next save_hit() call — keeps the bot alive even if MongoDB goes offline.
"""
import os
import logging
import threading
import time

logger = logging.getLogger(__name__)

_mongo_client = None
_collection = None
_enabled = False
_init_error: str = ""
_lock = threading.Lock()


def _try_connect() -> bool:
    """Attempt to connect to MongoDB. Returns True on success."""
    global _mongo_client, _collection, _enabled, _init_error
    url = os.environ.get("MONGODB_URL", "").strip()
    if not url:
        _init_error = "MONGODB_URL not set"
        return False
    try:
        import pymongo  # type: ignore
        client = pymongo.MongoClient(
            url,
            serverSelectionTimeoutMS=8000,
            connectTimeoutMS=8000,
            socketTimeoutMS=10000,
            retryWrites=True,
        )
        client.server_info()   # verify connection — raises on failure
        try:
            db_name = pymongo.uri_parser.parse_uri(url).get("database") or "netflix_checker"
        except Exception:
            db_name = "netflix_checker"
        db = client[db_name]
        col = db["hits"]
        try:
            col.create_index("user_id")
            col.create_index("saved_at")
            col.create_index("status")
        except Exception:
            pass  # indexes are best-effort; don't block startup
        _mongo_client = client
        _collection = col
        _enabled = True
        _init_error = ""
        logger.info("mongodb_store: connected — db=%s", db_name)
        return True
    except ImportError:
        _init_error = "pymongo not installed"
        logger.warning("mongodb_store: pymongo not installed — MongoDB disabled. "
                       "Install it with: pip install pymongo")
        return False
    except Exception as e:
        _init_error = str(e)
        logger.warning("mongodb_store: connection failed — %s", e)
        return False


def _init() -> None:
    _try_connect()


def is_enabled() -> bool:
    return _enabled


def init_error() -> str:
    """Return the last connection error string, or '' if connected OK."""
    return _init_error


def save_hit(result: dict, user_id: int = 0, source: str = "") -> bool:
    """Persist a hit/free/on_hold result to MongoDB. Returns True on success.
    If the collection is unreachable, attempts a single lazy reconnect before
    giving up — keeps the bot running if MongoDB was temporarily unavailable.
    """
    if not _enabled or _collection is None:
        return False
    doc = dict(result)
    doc.pop("nftoken", None)    # skip login-link tokens from DB
    doc["user_id"] = user_id
    doc["source"] = source
    doc["saved_at"] = time.time()
    try:
        with _lock:
            _collection.insert_one(doc)
        return True
    except Exception as e:
        logger.warning("mongodb_store: save_hit error — %s — attempting reconnect", e)
        # Try to reconnect once; if it works the next save_hit will succeed
        try:
            _try_connect()
        except Exception:
            pass
        return False


_init()
