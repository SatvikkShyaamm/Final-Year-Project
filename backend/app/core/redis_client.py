"""
Redis client setup.

Redis plays the same "intermediate layer" role described in the base paper
(ZTSAACM): a pub/sub + task-queue + fast key-value layer sitting between the
control plane (this FastAPI app) and, from Module 4 onward, the ACL
enforcement side. Module 1 only wires up connectivity.
"""
import redis

from app.core.config import get_settings

settings = get_settings()

redis_client = redis.Redis.from_url(settings.redis_url, decode_responses=True)


def check_redis_connection() -> bool:
    """Used by the /health endpoint to report real Redis connectivity."""
    try:
        return bool(redis_client.ping())
    except Exception:
        return False
