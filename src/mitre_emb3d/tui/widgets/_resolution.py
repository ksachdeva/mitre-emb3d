from mitre_emb3d._models import ThreatResolution

RESOLUTION_CSS: dict[ThreatResolution, str] = {
    ThreatResolution.NOT_INVESTIGATED: "not-investigated",
    ThreatResolution.NA: "na",
    ThreatResolution.MITIGATED: "mitigated",
    ThreatResolution.VULNERABLE: "vulnerable",
    ThreatResolution.CONDITIONALLY_MITIGATED: "conditionally-mitigated",
}

RESOLUTION_LABEL: dict[ThreatResolution, str] = {
    ThreatResolution.NOT_INVESTIGATED: "Not Investigated",
    ThreatResolution.NA: "N/A",
    ThreatResolution.MITIGATED: "Mitigated",
    ThreatResolution.VULNERABLE: "Vulnerable",
    ThreatResolution.CONDITIONALLY_MITIGATED: "Cond. Mitigated",
}

RESOLUTION_SHORT: dict[ThreatResolution, str] = {
    ThreatResolution.NOT_INVESTIGATED: "NI",
    ThreatResolution.NA: "NA",
    ThreatResolution.MITIGATED: " M",
    ThreatResolution.VULNERABLE: " V",
    ThreatResolution.CONDITIONALLY_MITIGATED: "CM",
}
