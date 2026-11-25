from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class FindingData:
    cve_id: str
    product: str = ""
    installed_version: str = ""
    fixed_version: str = ""
    origin: str = ""
    vendor_status: str = ""
    cvss: float | None = None
    severity: str = ""


@dataclass
class CpeQuery:
    """Produkt, das über die NVD per CPE-Versionsabgleich geprüft wird."""

    label: str  # Anzeige, z. B. "DSM 7.2.1-69057-5"
    cpe: str  # cpe:2.3:o:synology:diskstation_manager
    version: str


@dataclass
class DeviceData:
    external_id: str
    name: str
    kind: str = ""
    os: str = ""
    os_version: str = ""
    model: str = ""
    address: str = ""
    online: bool | None = None
    last_seen: datetime | None = None
    tenant_ref: str = ""  # z. B. Action1-Organisations-ID
    tenant_name: str = ""
    software: list[tuple[str, str, str, str]] = field(default_factory=list)  # name, version, vendor, ecosystem
    findings: list[FindingData] = field(default_factory=list)
    cpe_queries: list[CpeQuery] = field(default_factory=list)
    osv_ecosystem: str = ""
    osv_packages: list[tuple[str, str]] = field(default_factory=list)  # name, version
    raw: dict = field(default_factory=dict)


@dataclass
class CollectResult:
    devices: list[DeviceData] = field(default_factory=list)
    messages: list[str] = field(default_factory=list)
    # Bei Teilergebnissen keine Funde als „behoben" markieren
    complete: bool = True
    # CVEs, die nicht abgefragt werden konnten – deren Funde bleiben unverändert offen
    keep_cves: set[str] = field(default_factory=set)


class CollectorError(Exception):
    pass
