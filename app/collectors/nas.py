"""Synology (DSM) und QNAP (QTS / QuTS hero) per SSH.

Ermittelt Modell, Firmware und installierte Pakete. Firmware und bekannte
Pakete werden anschließend per CPE gegen die NVD geprüft.
"""
import re

from .base import CollectResult, CpeQuery, DeviceData
from .ssh import run_sections

# Paketname -> CPE-Präfix. Ergänzbar über das Feld „Zusätzliche CPE-Zuordnung" der Quelle.
SYNOLOGY_PACKAGES = {
    "PhotoStation": "cpe:2.3:a:synology:photo_station",
    "SurveillanceStation": "cpe:2.3:a:synology:surveillance_station",
    "AudioStation": "cpe:2.3:a:synology:audio_station",
    "DownloadStation": "cpe:2.3:a:synology:download_station",
    "MediaServer": "cpe:2.3:a:synology:media_server",
}
QNAP_PACKAGES = {
    "HybridBackup": "cpe:2.3:a:qnap:hybrid_backup_sync",
    "PhotoStation": "cpe:2.3:a:qnap:photo_station",
    "MusicStation": "cpe:2.3:a:qnap:music_station",
    "MultimediaConsole": "cpe:2.3:a:qnap:multimedia_console",
    "VideoStationPro": "cpe:2.3:a:qnap:video_station",
}

SYNO_SECTIONS = {
    "version": "cat /etc.defaults/VERSION",
    "hw": "cat /proc/sys/kernel/syno_hw_version",
    "synoinfo": "grep -E '^(upnpmodelname|unique)=' /etc/synoinfo.conf",
    "hostname": "hostname",
    "packages": "for f in /var/packages/*/INFO; do echo \"== $f\"; "
                "grep -E '^(package|version|displayname)=' \"$f\"; done",
}
QNAP_SECTIONS = {
    "version": "getcfg System Version",
    "number": "getcfg System Number",
    "build": "getcfg System 'Build Number'",
    "model": "getcfg System Model",
    "imodel": "getcfg System 'Internal Model'",
    "hostname": "hostname",
    "qpkg": "cat /etc/config/qpkg.conf",
}


def _kv(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"')
    return out


def extra_mapping(config: dict) -> dict[str, str]:
    m = {}
    for line in (config.get("cpe_map") or "").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            if v.strip().startswith("cpe:2.3:"):
                m[k.strip()] = v.strip()
    return m


# ------------------------------------------------------------- Synology
def parse_synology(sec: dict[str, str], config: dict) -> DeviceData:
    ver = _kv(sec.get("version", ""))
    info = _kv(sec.get("synoinfo", ""))
    pv = ver.get("productversion") or ".".join(
        x for x in (ver.get("majorversion"), ver.get("minorversion"), ver.get("micro")) if x)
    build = ver.get("buildnumber", "")
    fix = ver.get("smallfixnumber", "")
    full = pv
    if build:
        full += f"-{build}"
        if fix and fix != "0":
            full += f"-{fix}"
    model = sec.get("hw", "").strip() or info.get("upnpmodelname", "")
    name = config.get("display_name") or sec.get("hostname", "").strip() or config.get("host", "")
    dev = DeviceData(
        external_id=info.get("unique") or config.get("host", ""),
        name=name, kind="synology", os="Synology DSM", os_version=full, model=model,
        address=config.get("host", ""), online=True,
    )
    if pv:
        dev.cpe_queries.append(CpeQuery(f"DSM {full}", "cpe:2.3:o:synology:diskstation_manager", full))
    mapping = {**SYNOLOGY_PACKAGES, **extra_mapping(config)}
    pkg: dict = {}
    for line in sec.get("packages", "").splitlines() + ["== end"]:
        if line.startswith("== "):
            if pkg.get("package"):
                pid, pver = pkg["package"], pkg.get("version", "")
                dev.software.append((pkg.get("displayname") or pid, pver, "Synology", "synology-package"))
                if pid in mapping and pver:
                    dev.cpe_queries.append(CpeQuery(f"{pkg.get('displayname') or pid} {pver}", mapping[pid], pver))
            pkg = {}
        elif "=" in line:
            k, v = line.split("=", 1)
            pkg[k.strip()] = v.strip().strip('"')
    dev.software.insert(0, ("DiskStation Manager (DSM)", full, "Synology", "firmware"))
    return dev


# ----------------------------------------------------------------- QNAP
def parse_qnap(sec: dict[str, str], config: dict) -> DeviceData:
    version = sec.get("version", "").strip()
    number = sec.get("number", "").strip()
    build = sec.get("build", "").strip()
    hero = config.get("os") == "quts_hero"
    full = f"{version}.{number}" if version and number and number.isdigit() else version
    if hero and full and not full.lower().startswith("h"):
        full = "h" + full
    label_os = "QuTS hero" if hero else "QTS"
    model = sec.get("model", "").strip() or sec.get("imodel", "").strip()
    name = config.get("display_name") or sec.get("hostname", "").strip() or config.get("host", "")
    dev = DeviceData(
        external_id=config.get("host", ""), name=name, kind="qnap", os=f"QNAP {label_os}",
        os_version=f"{full} (Build {build})" if build else full, model=model,
        address=config.get("host", ""), online=True,
    )
    if full:
        dev.cpe_queries.append(CpeQuery(f"{label_os} {full}", "cpe:2.3:o:qnap:quts_hero" if hero
                                        else "cpe:2.3:o:qnap:qts", full))
    dev.software.append((label_os, full, "QNAP", "firmware"))
    mapping = {**QNAP_PACKAGES, **extra_mapping(config)}
    for name_, data in _ini(sec.get("qpkg", "")).items():
        qver = data.get("Version", "")
        disp = data.get("Display_Name") or name_
        dev.software.append((disp, qver, "QNAP", "qpkg"))
        if name_ in mapping and qver:
            dev.cpe_queries.append(CpeQuery(f"{disp} {qver}", mapping[name_], qver))
    return dev


def _ini(text: str) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    cur = None
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"^\[(.+)\]$", line)
        if m:
            cur = m.group(1)
            out[cur] = {}
        elif cur and "=" in line:
            k, v = line.split("=", 1)
            out[cur][k.strip()] = v.strip()
    return out


def collect(kind: str, config: dict, secrets: dict, timeout: float = 20):
    sections = SYNO_SECTIONS if kind == "synology" else QNAP_SECTIONS
    sec, new_key = run_sections(config, secrets, sections, timeout)
    dev = parse_synology(sec, config) if kind == "synology" else parse_qnap(sec, config)
    if not dev.os_version:
        raise_msg = ("Firmware-Version nicht lesbar – ist das wirklich ein "
                     f"{'Synology' if kind == 'synology' else 'QNAP'}-NAS und hat der Benutzer Leserechte?")
        from .base import CollectorError
        raise CollectorError(raise_msg)
    return CollectResult(devices=[dev], messages=[f"{dev.name}: {dev.os} {dev.os_version}"]), new_key
