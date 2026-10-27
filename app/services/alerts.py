import logging
from sqlalchemy.orm import Session
from app.models.all_models import Indicator, AlertStatus, AuditLog
from app.api.v1.endpoints.websocket import manager

logger = logging.getLogger("threatlens.alerts")


async def evaluate_indicator_for_alerting(indicator: Indicator, db: Session):
    """
    Evaluates new indicators against critical scoring thresholds, automatically
    generating security events and triggering real-time WebSocket alerts (FR-16).
    """
    CRITICAL_SCORE_THRESHOLD = 70

    if indicator.severity_score >= CRITICAL_SCORE_THRESHOLD:
        logger.info(
            f"High-severity vector verified [{indicator.value}]. Initializing alert lifecycle..."
        )

        # 1. Format structural payload for instant dashboard broadcast
        alert_payload = {
            "event": "NEW_HIGH_SEVERITY_ALERT",
            "indicator_id": str(indicator.id),
            "value": indicator.value,
            "type": indicator.type.value,
            "severity_score": indicator.severity_score,
            "tlp": indicator.tlp.value,
            "status": AlertStatus.NEW.value,
        }

        # 2. Push event data to the real-time manager for immediate fan-out
        await manager.broadcast_event(alert_payload)

        # 3. Append execution details to system logs for compliance record tracking
        audit_entry = AuditLog(
            actor_username="SYSTEM_CORRELATION_ENGINE",
            action="ALERT_GENERATED",
            details=f"Automated alert raised for high-severity indicator: {indicator.value} (Score: {indicator.severity_score})",
        )
        db.add(audit_entry)
        db.commit()
