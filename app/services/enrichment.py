import json
import logging
import httpx
from redis import Redis
from sqlalchemy.orm import Session
from app.core.config import settings
from app.models.all_models import Indicator, IndicatorSource, AuditLog
from app.services.scoring import calculate_severity_score

logger = logging.getLogger("threatlens.enrichment")

# Establish a connection to the high-performance caching layer
redis_client = Redis(host=settings.REDIS_HOST, port=settings.REDIS_PORT, db=0)
CACHE_TTL_SECONDS = 86400  # Enforce a strict 24-hour cache lifecycle limit


async def enrich_ip_indicator(
    indicator_value: str, db: Session, api_key: str = None
) -> dict:
    """
    Performs real-time IP reputation enrichment against AbuseIPDB.
    Maintains NFR-01 constraints (<300ms cached / <3s cold).
    """
    cache_key = f"enrichment:ip:{indicator_value}"

    # 1. Attempt Retrieval from Caching Engine (Sub-300ms Hot Path)
    cached_data = redis_client.get(cache_key)
    if cached_data:
        logger.info(f"Cache hit for IP indicator: {indicator_value}")
        return json.loads(cached_data.decode("utf-8"))

    # 2. Execute Remote API Requests (Cold Path)
    logger.info(f"Cache miss. Executing remote lookup for IP: {indicator_value}")
    url = "https://abuseipdb.com"
    headers = {
        "Accept": "application/json",
        "Key": api_key or "MOCK_DEVELOPMENT_ENVIRONMENT_KEY",
    }
    params = {"ipAddress": indicator_value, "maxAgeInDays": "90", "verbose": "true"}

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                url, headers=headers, params=params, timeout=2.5
            )
            if response.status_code == 200:
                raw_data = response.json().get("data", {})

                # Normalize response into structural threat profiles
                normalized_result = {
                    "abuse_score": raw_data.get("abuseConfidenceScore", 0),
                    "country_code": raw_data.get("countryCode", "US"),
                    "isp": raw_data.get("isp", "Unknown Provider"),
                    "total_reports": raw_data.get("totalReports", 0),
                    "verdict": "malicious"
                    if raw_data.get("abuseConfidenceScore", 0) > 50
                    else "clean",
                }

                # Write to the caching engine to accelerate subsequent queries
                redis_client.setex(
                    cache_key, CACHE_TTL_SECONDS, json.dumps(normalized_result)
                )
                return normalized_result

        except httpx.HTTPError as e:
            logger.error(f"External API communication crash during lookup: {str(e)}")

    # Fail-safe fallback layer prevents pipeline blockage
    return {
        "abuse_score": 0,
        "verdict": "unknown",
        "error": "Cold fetch execution failure",
    }
