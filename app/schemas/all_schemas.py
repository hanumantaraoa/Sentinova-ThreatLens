from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field, EmailStr
from typing import List, Optional
from app.models.all_models import UserRole, IOCType, TLPMarking, IOCStatus

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
    refresh_token: str = Field(..., examples=["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."])
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

class IndicatorResponse(BaseModel):
    """The complete representation of an IOC returned for analyst dashboards."""
    id: str = Field(..., examples=["b3b4a2f1-6c2e-4b9d-8cfa-123456789abc"])
    value: str = Field(..., examples=["185.220.101.4"])
    type: IOCType = Field(..., examples=[IOCType.IP])
    severity_score: int = Field(..., ge=0, le=100, examples=[75])
    confidence: int = Field(..., ge=0, le=100, examples=[80])
    tlp: TLPMarking = Field(..., examples=[TLPMarking.AMBER])
    status: IOCStatus = Field(..., examples=[IOCStatus.ACTIVE])
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime
    sources: List[SourceProvenanceSchema] = Field(default=[])

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
