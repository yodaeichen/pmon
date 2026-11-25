"""Priorisierung: KEV > EPSS > CVSS – verständlich auf Deutsch."""

PRIORITIES = {
    "sofort": {"label": "Sofort", "rank": 0, "css": "p-sofort",
               "hint": "Wird aktiv ausgenutzt oder ist kritisch mit hoher Angriffswahrscheinlichkeit."},
    "hoch": {"label": "Hoch", "rank": 1, "css": "p-hoch",
             "hint": "Hoher Schweregrad oder erhöhte Angriffswahrscheinlichkeit – zeitnah beheben."},
    "mittel": {"label": "Mittel", "rank": 2, "css": "p-mittel",
               "hint": "Mit dem nächsten regulären Update beheben."},
    "niedrig": {"label": "Niedrig", "rank": 3, "css": "p-niedrig",
                "hint": "Geringes Risiko – bei Gelegenheit beheben."},
}


def priority(cve) -> str:
    if cve is None:
        return "mittel"
    cvss = cve.cvss or 0
    epss = cve.epss or 0
    if cve.kev or (cvss >= 9 and epss >= 0.1):
        return "sofort"
    if cvss >= 7 or epss >= 0.1:
        return "hoch"
    if cvss >= 4 or cve.cvss is None:
        return "mittel"
    return "niedrig"


def sort_key(cve):
    p = PRIORITIES[priority(cve)]["rank"]
    return (p, -(cve.epss or 0) if cve else 0, -(cve.cvss or 0) if cve else 0)


def severity_de(sev: str) -> str:
    return {"CRITICAL": "Kritisch", "HIGH": "Hoch", "MEDIUM": "Mittel", "LOW": "Niedrig",
            "NONE": "Keine"}.get((sev or "").upper(), sev or "–")


def severity_from_score(score) -> str:
    if score is None:
        return ""
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW"
