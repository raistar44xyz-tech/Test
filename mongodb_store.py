"""
Optional MongoDB persistence for Netflix cookie checker hits.
Activated only when MONGODB_URL environment variable is set.
If pymongo is not installed or MONGODB_URL is not set, all calls are no-ops.
"""
import os
import logging
import threading
import time

logger = logging.getLogger(__name__)

_mongo_client = None
_collection = None
_enabled = False
_lock = threading.Lock()


def _init() -> None:
    global _mongo_client, _collection, _enabled
    url = os.environ.get("MONGODB_URL", "").strip()
    if not url:
        return
    try:
        import pymongo  # type: ignore
        client = pymongo.MongoClient(url, serverSelectionTimeoutMS=5000)
        client.server_info()   # verify connection
        db_name = pymongo.uri_parser.parse_uri(url).get("database") or "netflix_checker"
        db = client[db_name]
        col = db["hits"]
        col.create_index("user_id")
        col.create_index("saved_at")
        col.create_index("status")
        _mongo_client = client
        _collection = col
        _enabled = True
        logger.info("mongodb_store: connected — db=%s", db_name)
    except ImportError:
        logger.warning("mongodb_store: pymongo not installed — MongoDB disabled")
    except Exception as e:
        logger.warning("mongodb_store: connection failed — %s", e)


def is_enabled() -> bool:
    return _enabled


def save_hit(result: dict, user_id: int = 0, source: str = "") -> bool:
    """Persist a hit/free/on_hold result to MongoDB. Returns True on success."""
    if not _enabled or _collection is None:
        return False
    try:
        doc = dict(result)
        doc.pop("nftoken", None)    # skip login-link tokens from DB
        doc["user_id"] = user_id
        doc["source"] = source
        doc["saved_at"] = time.time()
        with _lock:
            _collection.insert_one(doc)
        return True
    except Exception as e:
        logger.warning("mongodb_store: save_hit error — %s", e)
        return False


_init()
