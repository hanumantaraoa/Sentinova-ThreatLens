import sys
import logging
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session

# Append project root to path environment arrays to resolve absolute routing paths cleanly
from app.core.database import SessionLocal, engine, Base
from app.core.security import get_password_hash
from app.models.all_models import (
    User,
    UserRole,
    Indicator,
    IndicatorSource,
    IOCType,
    TLPMarking,
    IOCStatus,
)

# Setup structural logging output parameters
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("threatlens.seed")


def seed_application_database(db: Session):
    """
    Seeds the PostgreSQL instance with base operational user layers, permissions profiles,
    and structured sample threat records matching initial capstone verification baselines.
    """
    logger.info("Initializing system seeding runtime sequence...")

    # =====================================================================
    # 1. CORE OPERATIONAL USER PROFILES SEEDING (Section 11 Matrix Met)
    # =====================================================================
    users_to_provision = [
        {
            "username": "priya_analyst",
            "password": "Password123!",
            "role": UserRole.SOC_ANALYST,
            "details": "Priya Nair — Tier-2 SOC Analyst Workflow Profile",
        },
        {
            "username": "daniel_responder",
            "password": "Password123!",
            "role": UserRole.INCIDENT_RESPONDER,
            "details": "Daniel Okafor — Incident Response Lead Profile",
        },
        {
            "username": "mei_hunter",
            "password": "Password123!",
            "role": UserRole.THREAT_HUNTER,
            "details": "Mei Lin Tan — Proactive Threat Hunter Profile",
        },
        {
            "username": "admin_engineer",
            "password": "AdminSecurePass!1",
            "role": UserRole.ADMIN,
            "details": "System Root Administrator Privilege Matrix Account",
        },
    ]

    seeded_users = {}
    for user_data in users_to_provision:
        existing_user = (
            db.query(User).filter(User.username == user_data["username"]).first()
        )
        if not existing_user:
            logger.info(
                f"Provisioning crypto identities for account value: {user_data['username']}"
            )
            new_user = User(
                username=user_data["username"],
                hashed_password=get_password_hash(user_data["password"]),
                role=user_data["role"],
                is_active=True,
            )
            db.add(new_user)
            seeded_users[user_data["username"]] = new_user
        else:
            logger.info(
                f"User identity profile already exists in ledger: {user_data['username']}"
            )
            seeded_users[user_data["username"]] = existing_user

    db.flush()  # Instantiates model states ahead of mapping relational dependencies

    # =====================================================================
    # 2. CANONICAL THREAT INTELLIGENCE OBSERVABLES (Section 2/21.4 Met)
    # =====================================================================
    threat_indicators = [
        {
            "value": "185.220.101.4",
            "type": IOCType.IP,
            "severity_score": 85,
            "confidence": 90,
            "tlp": TLPMarking.AMBER,
            "status": IOCStatus.ACTIVE,
            "source_feed": "AbuseIPDB Botnet Telemetry",
        },
        {
            "value": "bank-update-phishing.top",
            "type": IOCType.DOMAIN,
            "severity_score": 95,
            "confidence": 98,
            "tlp": TLPMarking.RED,
            "status": IOCStatus.ACTIVE,
            "source_feed": "URLhaus Direct Phishing Dump",
        },
        {
            "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "type": IOCType.HASH_SHA256,
            "severity_score": 65,
            "confidence": 75,
            "tlp": TLPMarking.GREEN,
            "status": IOCStatus.UNDER_REVIEW,
            "source_feed": "MalwareBazaar Ransomware Payload Signature",
        },
    ]

    for ioc_data in threat_indicators:
        existing_ioc = (
            db.query(Indicator).filter(Indicator.value == ioc_data["value"]).first()
        )
        if not existing_ioc:
            logger.info(
                f"Injecting test threat vector observables: {ioc_data['value']}"
            )
            new_ioc = Indicator(
                value=ioc_data["value"],
                type=ioc_data["type"],
                severity_score=ioc_data["severity_score"],
                confidence=ioc_data["confidence"],
                tlp=ioc_data["tlp"],
                status=ioc_data["status"],
                first_seen=datetime.now(timezone.utc) - timedelta(days=2),
                last_seen=datetime.now(timezone.utc),
            )
            db.add(new_ioc)
            db.flush()

            # Map historical source trace attributes back to target entity models
            initial_provenance = IndicatorSource(
                indicator_id=new_ioc.id,
                source_name=ioc_data["source_feed"],
                confidence=ioc_data["confidence"],
                timestamp=datetime.now(timezone.utc) - timedelta(days=2),
            )
            db.add(initial_provenance)
        else:
            logger.info(
                f"Observed baseline vector record already tracked: {ioc_data['value']}"
            )

    try:
        db.commit()
        logger.info(
            "✨ Database initialization seeding executed successfully without anomalies."
        )
    except Exception as exc:
        db.rollback()
        logger.error(
            f"❌ Structural breakdown during ingestion commit loops: {str(exc)}"
        )
        sys.exit(1)


if __name__ == "__main__":
    # Ensure physical layout data containers exist natively ahead of processing data
    Base.metadata.create_all(bind=engine)

    session = SessionLocal()
    try:
        seed_application_database(session)
    finally:
        session.close()
