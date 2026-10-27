from uuid import UUID
import time  # Fix: Added missing time import
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

from app.core.database import get_db
from app.api.deps import get_current_user, RoleChecker

# Fix: Added IOCType to the models import string
from app.models.all_models import (
    User,
    UserRole,
    Indicator,
    IndicatorSource,
    AuditLog,
    IOCStatus,
    IOCType,
)
from app.schemas.all_schemas import IndicatorResponse, IndicatorCreate, IndicatorUpdate
from app.services.scoring import calculate_severity_score
from app.services.alerts import evaluate_indicator_for_alerting
from app.services.enrichment import enrich_ip_indicator
from app.services.tasks import poll_urlhaus_intelligence_feed
from fastapi.responses import JSONResponse, StreamingResponse, Response
from app.services.reporting import (
    compile_stix21_intelligence_bundle,
    compile_flat_csv_intelligence_ledger,
)

router = APIRouter()


@router.get("", response_model=List[IndicatorResponse])
def fetch_indicators_queue(
    page: int = 1,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    offset = (page - 1) * limit

    indicators = (
        db.query(Indicator)
        .order_by(Indicator.severity_score.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    return indicators


# Fix: Turned this into an async def function so it handles the alert evaluation extension cleanly
@router.post("", response_model=IndicatorResponse, status_code=status.HTTP_201_CREATED)
async def ingest_threat_indicator(
    payload: IndicatorCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        RoleChecker([UserRole.ADMIN, UserRole.SECURITY_ENGINEER, UserRole.SOC_ANALYST])
    ),
):
    """
    Aggregates new intelligence inputs, deduplicates values, computes confidence scores,
    and writes to the record ledger.
    """
    # Deduplication check: Detect existing values within database boundary pools
    existing_ioc = db.query(Indicator).filter(Indicator.value == payload.value).first()

    if existing_ioc:
        # Append incoming source metadata record directly to the current indicator
        new_source = IndicatorSource(
            indicator_id=existing_ioc.id,
            source_name=f"Manual Triage - {current_user.username}",
            confidence=payload.confidence,
        )
        db.add(new_source)

        # Re-compute scoring algorithms based on updated feed values
        existing_ioc.severity_score = calculate_severity_score(
            existing_ioc, payload.confidence
        )
        db.commit()
        db.refresh(existing_ioc)

        # EXTENSION: Evaluate indicator severity parameters immediately on commit to push live alerts
        await evaluate_indicator_for_alerting(existing_ioc, db)
        return existing_ioc

    # Fresh entity provisioning logic path
    new_ioc = Indicator(
        value=payload.value,
        type=payload.type,
        confidence=payload.confidence,
        tlp=payload.tlp,
    )
    new_ioc.severity_score = calculate_severity_score(new_ioc, payload.confidence)

    db.add(new_ioc)
    db.flush()  # Secure primary key reference instantiation ahead of relational insertion loops

    initial_source = IndicatorSource(
        indicator_id=new_ioc.id,
        source_name=f"Manual Ingest - {current_user.username}",
        confidence=payload.confidence,
    )
    db.add(initial_source)

    # Stream structured state adjustments into the immutable logging container
    audit_entry = AuditLog(
        actor_username=current_user.username,
        action="INDICATOR_INGESTION",
        details=f"Provisioned canonical shape tracking parameters for target value: {payload.value}",
    )
    db.add(audit_entry)
    db.commit()
    db.refresh(new_ioc)

    # EXTENSION: Evaluate indicator severity parameters immediately on commit to push live alerts
    await evaluate_indicator_for_alerting(new_ioc, db)

    return new_ioc


@router.patch("/{indicator_id}", response_model=IndicatorResponse)
def update_indicator_state(
    indicator_id: str,
    payload: IndicatorUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        RoleChecker([UserRole.ADMIN, UserRole.INCIDENT_RESPONDER, UserRole.SOC_ANALYST])
    ),
):
    """Allows operational team profiles to manually adjust mitigation variables or tags."""
    ioc = db.query(Indicator).filter(Indicator.id == indicator_id).first()
    if not ioc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target indicator trace not found.",
        )

    # Apply data updates selectively
    update_data = payload.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(ioc, key, value)

    audit_entry = AuditLog(
        actor_username=current_user.username,
        action="INDICATOR_MODIFICATION",
        details=f"Modified field parameters across indicator ID: {indicator_id}",
    )
    db.add(audit_entry)
    db.commit()
    db.refresh(ioc)

    return ioc


@router.post("/{indicator_id}/enrich", response_model=dict)
async def trigger_on_demand_enrichment(
    indicator_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Triggers instant data enrichment lookups for specific tracked threat entities (FR-10)."""
    ioc = db.query(Indicator).filter(Indicator.id == indicator_id).first()
    if not ioc:
        raise HTTPException(
            status_code=404, detail="Target entity marker does not exist."
        )

    if ioc.type != IOCType.IP:
        raise HTTPException(
            status_code=400,
            detail="On-demand lookup optimization is restricted to IP vectors.",
        )

    # Execute lookups leveraging caching layers securely
    enrichment_data = await enrich_ip_indicator(ioc.value, db)

    # Audit changes explicitly
    audit_entry = AuditLog(
        actor_username=current_user.username,
        action="INDICATOR_ENRICHMENT_REFRESH",
        details=f"Manual enrichment check initiated for target: {ioc.value}",
    )
    db.add(audit_entry)
    db.commit()

    return {"indicator_value": ioc.value, "enrichment": enrichment_data}


@router.post("/feed/poll-trigger", status_code=202)
async def manual_trigger_async_feed(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        RoleChecker([UserRole.ADMIN, UserRole.SECURITY_ENGINEER])
    ),
):
    """Triggers background ingest loops directly from administrative panels (FR-05)."""
    await poll_urlhaus_intelligence_feed(db)
    return {"message": "Asynchronous thread polling completed successfully."}


# Fix: Removed the duplicate, incomplete ingest_threat_indicator code block that was sitting here.


@router.get("/export/stix", response_class=JSONResponse)
def export_intelligence_as_stix(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    """
    Compiles tracked threat intelligence profiles into a structured
    STIX 2.1 compliance package (FR-24 / Section 10.2).
    """
    # Enforce safe data boundaries: Fetch active entities to protect internal tracking states
    indicators = db.query(Indicator).filter(Indicator.status == IOCStatus.ACTIVE).all()
    stix_bundle = compile_stix21_intelligence_bundle(indicators)

    # Audit changes explicitly inside database audit records
    audit_entry = AuditLog(
        actor_username=current_user.username,
        action="INTEL_EXPORT_STIX",
        details=f"Exported {len(indicators)} intelligence objects inside a unified STIX 2.1 document.",
    )
    db.add(audit_entry)
    db.commit()

    return stix_bundle


@router.get("/export/csv")
def export_indicators_as_csv(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    """Generates standard tabular CSV streams to update downstream firewall blocklists or SIEM instances."""
    indicators = db.query(Indicator).filter(Indicator.status == IOCStatus.ACTIVE).all()
    csv_data = compile_flat_csv_intelligence_ledger(indicators)

    audit_entry = AuditLog(
        actor_username=current_user.username,
        action="INTEL_EXPORT_CSV",
        details=f"Exported tabular threat vector details for {len(indicators)} objects.",
    )
    db.add(audit_entry)
    db.commit()

    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=threatlens_export_{int(time.time())}.csv"
        },
    )
