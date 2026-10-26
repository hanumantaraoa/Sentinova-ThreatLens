import httpx
import logging
from sqlalchemy.orm import Session
from app.models.all_models import Indicator, IndicatorSource, IOCType, IOCStatus, AuditLog
from app.services.scoring import calculate_severity_score

logger = logging.getLogger("threatlens.tasks")


async def poll_urlhaus_intelligence_feed(db: Session):
    """
    Asynchronously extracts, normalizes, and injects fresh URL indicators
    from public URLhaus intelligence lines (FR-01 Compliance).
    """
    feed_url = "https://abuse.ch"
    logger.info("Initializing automated polling sequence against URLhaus dump arrays...")

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(feed_url, timeout=5.0)
            if response.status_code != 200:
                logger.error(f"Failed to fetch remote intelligence assets. Status: {response.status_code}")
                return

            raw_lines = response.text.splitlines()
            ingest_count = 0

            for line in raw_lines:
                # Discard comment parameters out of text payload structures
                if not line or line.startswith("#"):
                    continue

                target_url = line.strip()
                if ingest_count >= 10:  # Restrict processing slices for baseline run execution safety
                    break

                # -------------------------------------------------------------
                # DEDUPLICATION & WRITING SEQUENCES (FR-03)
                # -------------------------------------------------------------
                existing_ioc = db.query(Indicator).filter(Indicator.value == target_url).first()

                if existing_ioc:
                    # Append source signature logs natively to tracking maps
                    new_source = IndicatorSource(
                        indicator_id=existing_ioc.id,
                        source_name="URLhaus Asynchronous Worker Feed",
                        confidence=85
                    )
                    db.add(new_source)
                    existing_ioc.severity_score = calculate_severity_score(existing_ioc, 85)
                else:
                    new_ioc = Indicator(
                        value=target_url,
                        type=IOCType.URL,
                        confidence=85,
                        status=IOCStatus.ACTIVE
                    )
                    new_ioc.severity_score = calculate_severity_score(new_ioc, 85)
                    db.add(new_ioc)
                    db.flush()

                    initial_source = IndicatorSource(
                        indicator_id=new_ioc.id,
                        source_name="URLhaus Asynchronous Worker Feed",
                        confidence=85
                    )
                    db.add(initial_source)

                ingest_count += 1

            db.commit()

            # Record execution metadata cleanly into your append-only system trail
            audit_entry = AuditLog(
                actor_username="SYSTEM_ASYNC_WORKER",
                action="FEED_POLLING_COMPLETED",
                details=f"Successfully extracted and integrated {ingest_count} threat indicators out of URLhaus lines."
            )
            db.add(audit_entry)
            db.commit()

            logger.info(f"Ingestion batch cycle closed. Ingested records: {ingest_count}")

        except httpx.HTTPError as exc:
            logger.error(f"System failure while pulling from threat line: {str(exc)}")
