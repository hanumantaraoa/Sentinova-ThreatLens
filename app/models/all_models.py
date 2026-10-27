import uuid
from enum import Enum
from sqlalchemy import (
    Column,
    String,
    Integer,
    SmallInteger,
    DateTime,
    Enum as SQLEnum,
    ForeignKey,
    Text,
    Boolean,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base


class UserRole(str, Enum):
    ADMIN = "Administrator"
    SECURITY_ENGINEER = "Security Engineer"
    INCIDENT_RESPONDER = "Incident Responder"
    THREAT_HUNTER = "Threat Hunter"
    SOC_ANALYST = "SOC Analyst"
    EXECUTIVE = "Executive"


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    CVE = "cve"


class TLPMarking(str, Enum):
    CLEAR = "clear"
    GREEN = "green"
    AMBER = "amber"
    RED = "red"


class IOCStatus(str, Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    WHITELISTED = "whitelisted"
    UNDER_REVIEW = "under_review"


class AlertStatus(str, Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in-progress"
    RESOLVED = "resolved"
    CLOSED = "closed"


class User(Base):
    __tablename__ = "users"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(SQLEnum(UserRole), nullable=False, default=UserRole.SOC_ANALYST)
    is_active = Column(Boolean, default=True)


class Indicator(Base):
    __tablename__ = "indicators"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    value = Column(Text, unique=True, index=True, nullable=False)
    type = Column(SQLEnum(IOCType), index=True, nullable=False)
    severity_score = Column(SmallInteger, index=True, default=0)
    confidence = Column(SmallInteger, default=0)
    tlp = Column(SQLEnum(TLPMarking), default=TLPMarking.CLEAR)
    status = Column(SQLEnum(IOCStatus), index=True, default=IOCStatus.ACTIVE)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    sources = relationship(
        "IndicatorSource", back_populates="indicator", cascade="all, delete-orphan"
    )


class IndicatorSource(Base):
    __tablename__ = "indicator_sources"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    indicator_id = Column(
        UUID(as_uuid=True),
        ForeignKey("indicators.id", ondelete="CASCADE"),
        nullable=False,
    )
    source_name = Column(String, nullable=False)
    confidence = Column(SmallInteger, default=50)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

    indicator = relationship("Indicator", back_populates="sources")


class AuditLog(Base):
    __tablename__ = "audit_log"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    actor_username = Column(String, nullable=True)
    action = Column(String, nullable=False)
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
