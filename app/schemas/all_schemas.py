import sys

# Forces eager compilation of Pydantic models for Python 3.14 compatibility

# --- ADD THIS TO THE TOP OF ALL_SCHEMAS.PY ---
from typing import List, Optional, Any, Dict, Union  # Fix: Ensure Optional is imported!
from datetime import datetime
from app.models.all_models import UserRole, IOCType, TLPMarking, IOCStatus
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field, EmailStr, field_validator

# =====================================================================
# AUTHENTICATION & ACCESS SCHEMAS
# =====================================================================


class UserLogin(BaseModel):
    """Validates incoming authentication requests at the API boundary."""

    username: str = Field(..., min_length=3, max_length=50, examples=["priya_analyst"])
    password: str = Field(..., min_length=8, examples=["SecurePass123!"])


class TokenResponse(BaseModel):
    """Returns stateless session verification variables to clients."""

    access_token: str = Field(..., examples=["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."])
    refresh_token: str = Field(
        ..., examples=["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."]
    )
    token_type: str = Field(default="Bearer", examples=["Bearer"])


class UserProfileResponse(BaseModel):
    """Projects user metadata out of the database securely without leaking crypto states."""

    username: str = Field(..., examples=["priya_analyst"])
    role: UserRole = Field(..., examples=[UserRole.SOC_ANALYST])
    is_active: bool = Field(..., examples=[True])

    model_config = ConfigDict(from_attributes=True)


# =====================================================================
# THREAT INTELLIGENCE PROVENANCE & INDICATOR SCHEMAS
# =====================================================================


class SourceProvenanceSchema(BaseModel):
    """Tracks multi-feed source reliability metrics for deduplicated entries."""

    source_name: str = Field(..., examples=["AlienVault OTX"])
    confidence: int = Field(..., ge=0, le=100, examples=[80])
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


class IndicatorCreate(BaseModel):
    """Enforces type and payload validation for threat vectors added to the pool."""

    value: str = Field(..., min_length=1, examples=["185.220.101.4"])
    type: IOCType = Field(..., examples=[IOCType.IP])
    confidence: int = Field(default=50, ge=0, le=100, examples=[80])
    tlp: TLPMarking = Field(default=TLPMarking.CLEAR, examples=[TLPMarking.AMBER])


class IndicatorUpdate(BaseModel):
    """Validates properties modified during analysis operations."""

    severity_score: Optional[int] = Field(None, ge=0, le=100, examples=[75])
    status: Optional[IOCStatus] = Field(None, examples=[IOCStatus.UNDER_REVIEW])
    tlp: Optional[TLPMarking] = Field(None, examples=[TLPMarking.RED])


# A clean helper function to safely map UUIDs or any other type to a string


class IndicatorResponse(BaseModel):
    id: str  # Kept as str to match your front-end API expectations
    value: str
    type: str

    # ... keep the rest of your model's existing fields exactly as they are ...

    # Automatically converts database UUID objects to strings before validation checks run
    @field_validator("id", mode="before")
    @classmethod
    def transform_uuid_to_str(cls, value: Any) -> str:
        if isinstance(value, UUID):
            return str(value)

        # Standard layout to read SQLAlchemy ORM objects seamlessly

        model_config = ConfigDict(from_attributes=True)


# =====================================================================
# SYSTEMIC FILTERING & ERROR PACKAGES
# =====================================================================


class FilteredIndicatorQuery(BaseModel):
    """Structure configuration for search queries and list filters."""

    type: Optional[IOCType] = None
    status: Optional[IOCStatus] = None
    min_severity: int = Field(default=0, ge=0, le=100)
    page: int = Field(default=1, ge=1)
    limit: int = Field(default=50, ge=1, le=100)


class ErrorEnvelopeSchema(BaseModel):
    """Standardized exception footprint matching Section 10.4 configurations."""

    error_code: str = Field(..., examples=["ACCESS_DENIED"])
    message: str = Field(..., examples=["Account lacks required RBAC privileges."])
    correlation_id: str = Field(..., examples=["REQ-9981-ABC"])


for schema in [IndicatorCreate, IndicatorUpdate, IndicatorResponse]:
    try:
        # Pass the current module context explicitly into the builder namespace
        schema.model_rebuild(module=__name__)
    except Exception:
        pass


# Force Pydantic to cleanly compile lazy type evaluations for Python 3.14 compatibility
# --- ABSOLUTE BOTTOM OF ALL_SCHEMAS.PY ---
try:
    IndicatorCreate.model_rebuild()
    IndicatorUpdate.model_rebuild()
    IndicatorResponse.model_rebuild()
except Exception:
    pass
