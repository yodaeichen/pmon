"""Linux-Server/-VMs/Proxmox per SSH – Paketliste wird über OSV.dev geprüft."""
import re

from .base import CollectorError, CollectResult, DeviceData
from .ssh import run_sections

SECTIONS = {
    "osrelease": "cat /etc/os-release",
    "hostname": "hostname",
    "machineid": "cat /etc/machine-id",
    "pve": "pveversion",
    "dpkg": "command -v dpkg-query >/dev/null && dpkg-query -W -f='${db:Status-Abbrev}\\t${Package}\\t${Version}\\t${source:Package}\\t${source:Version}\\n'",
    "rpm": "command -v dpkg-query >/dev/null || { command -v rpm >/dev/null && rpm -qa --qf '%{NAME}\\t%{EPOCHNUM}\\t%{VERSION}-%{RELEASE}\\n'; }",
    "apk": "command -v apk >/dev/null && apk list -I",
}


def _kv(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"')
    return out


def osv_ecosystem(osr: dict) -> str:
    os_id = osr.get("ID", "").lower()
    ver = osr.get("VERSION_ID", "")
    major = ver.split(".")[0]
    if os_id == "debian" and major:
        return f"Debian:{major}"
    if os_id == "ubuntu" and ver:
        try:
            year, month = ver.split(".")[:2]
            lts = month == "04" and int(year) % 2 == 0
        except ValueError:
            lts = False
        return f"Ubuntu:{ver}:LTS" if lts else f"Ubuntu:{ver}"
    if os_id == "almalinux" and major:
        return f"AlmaLinux:{major}"
    if os_id == "rocky" and major:
        return f"Rocky Linux:{major}"
    if os_id == "alpine" and ver:
        return "Alpine:v" + ".".join(ver.split(".")[:2])
    return ""


def parse(sec: dict[str, str], config: dict) -> DeviceData:
    osr = _kv(sec.get("osrelease", ""))
    pve = sec.get("pve", "").strip()
    name = config.get("display_name") or sec.get("hostname", "").strip() or config.get("host", "")
    dev = DeviceData(
        external_id=sec.get("machineid", "").strip() or config.get("host", ""),
        name=name, kind="proxmox" if pve.startswith("pve-manager") else "linux",
        os=osr.get("PRETTY_NAME", "Linux"), os_version=osr.get("VERSION_ID", ""),
        model=pve.split(" (")[0] if pve else "", address=config.get("host", ""), online=True,
    )
    dev.osv_ecosystem = osv_ecosystem(osr)
    pkgs: dict[str, str] = {}
    for line in sec.get("dpkg", "").splitlines():
        parts = line.split("\t")
        if len(parts) < 5 or not parts[0].startswith("ii"):
            continue
        _, binpkg, binver, srcpkg, srcver = parts[:5]
        dev.software.append((binpkg, binver, "", "deb"))
        # OSV (Debian/Ubuntu) arbeitet mit Quellpaketen
        src = (srcpkg or binpkg).split(" ")[0]
        pkgs[src] = srcver or binver
    for line in sec.get("rpm", "").splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        n, epoch, vr = parts
        v = vr if epoch in ("", "0", "(none)") else f"{epoch}:{vr}"
        dev.software.append((n, v, "", "rpm"))
        pkgs[n] = v
    for line in sec.get("apk", "").splitlines():
        m = re.match(r"^(.+)-([^-]+-r\d+) \S+ \{([^}]+)\}", line)
        if m:
            n, v, origin = m.groups()
            dev.software.append((n, v, "", "apk"))
            pkgs[origin] = v
    dev.osv_packages = sorted(pkgs.items())
    return dev


def collect(config: dict, secrets: dict, timeout: float = 20):
    sec, new_key = run_sections(config, secrets, SECTIONS, timeout)
    dev = parse(sec, config)
    if not dev.software:
        raise CollectorError("Keine Paketliste erhalten (dpkg, rpm oder apk erforderlich).")
    msg = f"{dev.name}: {dev.os}, {len(dev.software)} Pakete"
    if not dev.osv_ecosystem:
        msg += " – Distribution wird von OSV nicht unterstützt, nur Inventar"
    return CollectResult(devices=[dev], messages=[msg]), new_key
