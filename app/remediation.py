"""Konkrete Abhilfe-Hinweise je Fund – abhängig von Gerätetyp und Quelle."""

VENDOR_LINKS = {
    "synology": ("Synology Security Advisories", "https://www.synology.com/de-de/security/advisory"),
    "qnap": ("QNAP Security Advisories", "https://www.qnap.com/de-de/security-advisories"),
}


def steps(finding, device, cve) -> list[str]:
    out: list[str] = []
    kind = device.kind if device else ""
    fix = (finding.fixed_version or "").strip()
    product = finding.product or "die betroffene Software"

    if cve is not None and cve.kev:
        due = f" (CISA-Frist für US-Behörden: {cve.kev_due})" if cve.kev_due else ""
        out.append(f"Wird laut CISA aktiv ausgenutzt{due} – vorrangig behandeln.")
        if cve.kev_ransomware == "Known":
            out.append("Bekannt aus Ransomware-Kampagnen: Erreichbarkeit aus dem Internet sofort prüfen.")

    if finding.origin == "action1":
        if fix:
            out.append(f"Update „{fix}“ über Action1 verteilen (Patch Management → Updates oder Schwachstelle → Remediate).")
        else:
            out.append(f"{product} auf die aktuelle Version aktualisieren; ist kein Update verfügbar, "
                       "in Action1 eine Kompensationsmaßnahme (Control) dokumentieren.")
    elif kind == "synology":
        if finding.product.startswith("DSM"):
            out.append("DSM aktualisieren: Systemsteuerung → Aktualisieren & Wiederherstellen"
                       + (f" – benötigt wird {fix}." if fix else "."))
        else:
            out.append(f"Paket im Paket-Zentrum aktualisieren ({product})" + (f", {fix}." if fix else ".")
                       + " Wird es nicht gebraucht, besser deinstallieren.")
        out.append("QuickConnect/Portfreigaben prüfen – das NAS möglichst nicht direkt aus dem Internet erreichbar machen.")
    elif kind == "qnap":
        if finding.product.startswith(("QTS", "QuTS")):
            out.append("Firmware aktualisieren: Systemsteuerung → System → Firmware-Aktualisierung"
                       + (f" – benötigt wird {fix}." if fix else "."))
        else:
            out.append(f"App im App Center aktualisieren ({product})" + (f", {fix}." if fix else ".")
                       + " Nicht benötigte Apps entfernen.")
        out.append("myQNAPcloud, UPnP und Portfreigaben prüfen – QNAP-Geräte werden häufig von Ransomware angegriffen.")
    elif kind in ("linux", "proxmox"):
        pkg = product.split(" ")[0]
        os_name = (device.os or "") if device else ""
        if kind == "proxmox" or "Debian" in os_name or "Ubuntu" in os_name:
            out.append(f"Paket aktualisieren: apt update && apt full-upgrade (Quellpaket {pkg}"
                       + (f", behoben in {fix})." if fix else ")."))
        else:
            out.append(f"Paket {pkg} mit dem Paketmanager aktualisieren" + (f" (behoben in {fix})." if fix else "."))
        out.append("Danach betroffene Dienste neu starten bzw. bei Kernel/Bibliotheken neu booten (needrestart hilft).")
    else:
        out.append(f"{product} aktualisieren" + (f" ({fix})." if fix else "."))

    if cve is not None and cve.kev_action and cve.kev:
        out.append(f"CISA-Empfehlung: {cve.kev_action}")
    return out


def vendor_link(device):
    return VENDOR_LINKS.get(device.kind) if device else None
