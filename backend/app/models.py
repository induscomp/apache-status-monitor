from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def now() -> datetime:
    return datetime.now(UTC)


def identifier() -> str:
    return str(uuid4())


class Base(DeclarativeBase):
    pass


class Admin(Base):
    __tablename__ = "admins"
    __table_args__ = (CheckConstraint("id = 1", name="single_administrator"),)
    # Singleton administrator, enforced by CLI and API scope. No public registration.
    id: Mapped[int] = mapped_column(primary_key=True, default=1)
    email: Mapped[str] = mapped_column(String(254), unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    totp_encrypted: Mapped[str] = mapped_column(Text)
    last_totp_step: Mapped[int] = mapped_column(default=-1)
    recovery_hashes: Mapped[list] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class AuthSession(Base):
    __tablename__ = "auth_sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    admin_id: Mapped[int] = mapped_column(ForeignKey("admins.id", ondelete="CASCADE"))
    csrf_token: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class RateBucket(Base):
    __tablename__ = "rate_buckets"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    window: Mapped[int] = mapped_column(Integer, primary_key=True)
    count: Mapped[int] = mapped_column(default=1)


class Server(Base):
    __tablename__ = "servers"
    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=identifier)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    description: Mapped[str] = mapped_column(String(1000), default="")
    tags: Mapped[list] = mapped_column(JSONB, default=list)
    alert_settings: Mapped[dict] = mapped_column(JSONB, default=dict)
    archived: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Service(Base):
    __tablename__ = "services"
    __table_args__ = (UniqueConstraint("server_id", "name"),)
    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=identifier)
    server_id: Mapped[str] = mapped_column(ForeignKey("servers.id"), index=True)
    name: Mapped[str] = mapped_column(String(100))
    kind: Mapped[str] = mapped_column(String(30))
    url: Mapped[str] = mapped_column(String(2048))
    interval_seconds: Mapped[int] = mapped_column(default=300)
    enabled: Mapped[bool] = mapped_column(default=True)
    archived: Mapped[bool] = mapped_column(default=False)
    revision: Mapped[int] = mapped_column(default=1)
    options: Mapped[dict] = mapped_column(JSONB, default=dict)
    credentials_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ServiceRevision(Base):
    __tablename__ = "service_revisions"
    service_id: Mapped[str] = mapped_column(ForeignKey("services.id"), primary_key=True)
    revision: Mapped[int] = mapped_column(primary_key=True)
    configuration: Mapped[dict] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=identifier)
    action: Mapped[str] = mapped_column(String(60))
    target_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)


class ComponentHeartbeat(Base):
    __tablename__ = "component_heartbeats"
    name: Mapped[str] = mapped_column(String(30), primary_key=True)
    seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ApacheObservation(Base):
    __tablename__ = "apache_observations"
    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=identifier)
    service_id: Mapped[str] = mapped_column(ForeignKey("services.id"), index=True)
    revision: Mapped[int] = mapped_column()
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    status: Mapped[str] = mapped_column(String(20))
    metrics: Mapped[dict] = mapped_column(JSONB, default=dict)
    warnings: Mapped[list] = mapped_column(JSONB, default=list)
    workers: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    raw_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)


class MrtgDiscovery(Base):
    __tablename__ = "mrtg_discoveries"
    service_id: Mapped[str] = mapped_column(ForeignKey("services.id"), primary_key=True)
    revision: Mapped[int] = mapped_column(default=0)
    attempted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    succeeded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    requested: Mapped[bool] = mapped_column(default=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class MrtgMetric(Base):
    __tablename__ = "mrtg_metrics"
    __table_args__ = (UniqueConstraint("service_id", "url"),)
    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=identifier)
    service_id: Mapped[str] = mapped_column(ForeignKey("services.id"), index=True)
    url: Mapped[str] = mapped_column(String(2048))
    name: Mapped[str] = mapped_column(String(200))
    selected: Mapped[bool] = mapped_column(default=True)
    present: Mapped[bool] = mapped_column(default=True)
    revision: Mapped[int] = mapped_column(default=1)
    configuration: Mapped[dict] = mapped_column(JSONB, default=dict)


class MrtgObservation(Base):
    __tablename__ = "mrtg_observations"
    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=identifier)
    metric_id: Mapped[str] = mapped_column(ForeignKey("mrtg_metrics.id"), index=True)
    service_id: Mapped[str] = mapped_column(ForeignKey("services.id"), index=True)
    revision: Mapped[int] = mapped_column()
    metric_revision: Mapped[int] = mapped_column()
    configuration: Mapped[dict] = mapped_column(JSONB, default=dict)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    source_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    source_time_text: Mapped[str | None] = mapped_column(String(200), nullable=True)
    status: Mapped[str] = mapped_column(String(20))
    values: Mapped[list] = mapped_column(JSONB, default=list)
    warnings: Mapped[list] = mapped_column(JSONB, default=list)
    raw_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)


class ServerFrame(Base):
    __tablename__ = "server_frames"
    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=identifier)
    observation_id: Mapped[str] = mapped_column(Uuid(as_uuid=False), unique=True)
    server_id: Mapped[str] = mapped_column(ForeignKey("servers.id"), index=True)
    service_id: Mapped[str] = mapped_column(ForeignKey("services.id"), index=True)
    revision: Mapped[int] = mapped_column()
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    valid: Mapped[bool] = mapped_column(default=False)
    metrics: Mapped[dict] = mapped_column(JSONB, default=dict)
    domains: Mapped[dict] = mapped_column(JSONB, default=dict)
    details: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    resources: Mapped[dict] = mapped_column(JSONB, default=dict)
    warnings: Mapped[list] = mapped_column(JSONB, default=list)


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=identifier)
    server_id: Mapped[str] = mapped_column(ForeignKey("servers.id"), index=True)
    service_id: Mapped[str] = mapped_column(ForeignKey("services.id"))
    subject: Mapped[str] = mapped_column(String(300))
    kind: Mapped[str] = mapped_column(String(30))
    status: Mapped[str] = mapped_column(String(20), default="open")
    severity: Mapped[str] = mapped_column(String(20), default="warning")
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    evidence: Mapped[dict] = mapped_column(JSONB, default=dict)


class AnomalyState(Base):
    __tablename__ = "anomaly_states"
    __table_args__ = (UniqueConstraint("service_id", "subject"),)
    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=identifier)
    service_id: Mapped[str] = mapped_column(ForeignKey("services.id"))
    subject: Mapped[str] = mapped_column(String(300))
    last_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    bad: Mapped[int] = mapped_column(default=0)
    good: Mapped[int] = mapped_column(default=0)
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id"), nullable=True)


class NotificationConfig(Base):
    __tablename__ = "notification_config"
    id: Mapped[int] = mapped_column(primary_key=True, default=1)
    encrypted: Mapped[str] = mapped_column(Text)


class EmailDelivery(Base):
    __tablename__ = "email_deliveries"
    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=identifier)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"))
    transition: Mapped[str] = mapped_column(String(30))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    status: Mapped[str] = mapped_column(String(20), default="pending")
    error: Mapped[str | None] = mapped_column(String(200), nullable=True)


class GoAccessReport(Base):
    __tablename__ = "goaccess_reports"
    __table_args__ = (UniqueConstraint("service_id", "revision", "fingerprint"),)
    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=identifier)
    service_id: Mapped[str] = mapped_column(ForeignKey("services.id"), index=True)
    revision: Mapped[int] = mapped_column()
    fingerprint: Mapped[str] = mapped_column(String(64))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    generated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    summary: Mapped[dict] = mapped_column(JSONB)
    panels: Mapped[dict] = mapped_column(JSONB)


class GoAccessState(Base):
    __tablename__ = "goaccess_states"
    service_id: Mapped[str] = mapped_column(ForeignKey("services.id"), primary_key=True)
    revision: Mapped[int] = mapped_column()
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(20))
    report_id: Mapped[str | None] = mapped_column(ForeignKey("goaccess_reports.id"), nullable=True)
    warnings: Mapped[list] = mapped_column(JSONB, default=list)


class ServiceCheck(Base):
    """Polling outcome history; never contains report bodies or credentials."""

    __tablename__ = "service_checks"
    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=identifier)
    service_id: Mapped[str] = mapped_column(ForeignKey("services.id"), index=True)
    revision: Mapped[int] = mapped_column()
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    status: Mapped[str] = mapped_column(String(20))


class SupportReport(Base):
    __tablename__ = "support_reports"
    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=identifier)
    server_id: Mapped[str] = mapped_column(ForeignKey("servers.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    attempted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="draft")
    encrypted: Mapped[str] = mapped_column(Text)
    error: Mapped[str | None] = mapped_column(String(200), nullable=True)
