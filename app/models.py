from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


user_tenants = Table(
    "user_tenants",
    Base.metadata,
    Column("user_id", ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("tenant_id", ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True),
)

ROLES = {
    "admin": "Administrator – alles, inkl. Benutzer und Einstellungen",
    "techniker": "Techniker – Kunden, Quellen und Scans verwalten",
    "leser": "Leser – nur ansehen (z. B. Zugang für Kunden)",
}


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    display_name = Column(String(120), default="")
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="leser")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)
    last_login = Column(DateTime)
    # Leer = alle Kunden sichtbar (nur für Admin/Techniker sinnvoll)
    tenants = relationship("Tenant", secondary=user_tenants, lazy="selectin")

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    @property
    def can_manage(self) -> bool:
        return self.role in ("admin", "techniker")


class Tenant(Base):
    """Kunde/Mandant – z. B. eine Firma oder Löschgruppe."""

    __tablename__ = "tenants"
    id = Column(Integer, primary_key=True)
    name = Column(String(160), nullable=False)
    note = Column(Text, default="")
    action1_org_id = Column(String(80), index=True)
    created_at = Column(DateTime, default=utcnow)
    devices = relationship("Device", back_populates="tenant", cascade="all, delete-orphan")


class Source(Base):
    __tablename__ = "sources"
    id = Column(Integer, primary_key=True)
    name = Column(String(160), nullable=False)
    kind = Column(String(20), nullable=False)  # action1 | synology | qnap | linux
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="SET NULL"))
    enabled = Column(Boolean, default=True)
    interval_minutes = Column(Integer, default=60)
    config_json = Column(Text, default="{}")
    secret_enc = Column(Text, default="")
    last_run = Column(DateTime)
    last_status = Column(String(20))  # ok | fehler | laeuft
    last_message = Column(Text, default="")
    next_run = Column(DateTime)
    tenant = relationship("Tenant")


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (UniqueConstraint("source_id", "external_id"),)
    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"))
    source_id = Column(Integer, ForeignKey("sources.id", ondelete="CASCADE"))
    external_id = Column(String(200), nullable=False)
    name = Column(String(200), nullable=False)
    kind = Column(String(30), default="")  # windows | linux | mac | synology | qnap
    os = Column(String(200), default="")
    os_version = Column(String(120), default="")
    model = Column(String(120), default="")
    address = Column(String(200), default="")
    online = Column(Boolean)
    last_seen = Column(DateTime)
    last_scan = Column(DateTime)
    raw_json = Column(Text, default="{}")
    tenant = relationship("Tenant", back_populates="devices")
    source = relationship("Source")
    software = relationship("Software", cascade="all, delete-orphan", lazy="select")
    findings = relationship("Finding", viewonly=True, lazy="select")


class Software(Base):
    __tablename__ = "software"
    id = Column(Integer, primary_key=True)
    device_id = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    name = Column(String(300), nullable=False)
    version = Column(String(120), default="")
    vendor = Column(String(200), default="")
    ecosystem = Column(String(60), default="")


class Cve(Base):
    __tablename__ = "cves"
    id = Column(String(40), primary_key=True)
    description = Column(Text, default="")
    cvss = Column(Float)
    severity = Column(String(20), default="")
    vector = Column(String(200), default="")
    cwe = Column(String(200), default="")
    published = Column(DateTime)
    references_json = Column(Text, default="[]")
    epss = Column(Float)
    epss_percentile = Column(Float)
    kev = Column(Boolean, default=False)
    kev_date_added = Column(String(20), default="")
    kev_due = Column(String(20), default="")
    kev_ransomware = Column(String(20), default="")
    kev_action = Column(Text, default="")
    kev_name = Column(Text, default="")
    nvd_fetched_at = Column(DateTime)
    epss_fetched_at = Column(DateTime)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("device_id", "cve_id", "product"),)
    id = Column(Integer, primary_key=True)
    device_id = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    source_id = Column(Integer, ForeignKey("sources.id", ondelete="CASCADE"), index=True)
    cve_id = Column(String(40), ForeignKey("cves.id"), index=True)
    product = Column(String(300), default="")
    installed_version = Column(String(200), default="")
    fixed_version = Column(String(300), default="")
    origin = Column(String(20), default="")  # action1 | nvd | osv
    vendor_status = Column(String(60), default="")  # z. B. Action1-Remediation-Status
    status = Column(String(20), default="open", index=True)  # open | resolved | accepted
    note = Column(Text, default="")
    first_seen = Column(DateTime, default=utcnow)
    last_seen = Column(DateTime, default=utcnow)
    resolved_at = Column(DateTime)
    notified = Column(Boolean, default=False)
    device = relationship("Device")
    cve = relationship("Cve", lazy="joined")


class Setting(Base):
    __tablename__ = "settings"
    key = Column(String(80), primary_key=True)
    value = Column(Text, default="")


class ScanRun(Base):
    __tablename__ = "scan_runs"
    id = Column(Integer, primary_key=True)
    source_id = Column(Integer, ForeignKey("sources.id", ondelete="CASCADE"), index=True)
    started = Column(DateTime, default=utcnow)
    finished = Column(DateTime)
    status = Column(String(20), default="laeuft")
    message = Column(Text, default="")
    devices = Column(Integer, default=0)
    new_findings = Column(Integer, default=0)
    resolved_findings = Column(Integer, default=0)
    source = relationship("Source")


class OsvCache(Base):
    __tablename__ = "osv_cache"
    id = Column(String(80), primary_key=True)
    data = Column(Text, default="{}")
    fetched_at = Column(DateTime, default=utcnow)
