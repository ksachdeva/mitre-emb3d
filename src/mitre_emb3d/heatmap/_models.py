from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import List, Optional

from pydantic import BaseModel, Field

from mitre_emb3d._models import Emb3dCategory, MitigationLevel


class MitigationResolution(StrEnum):
    NOT_INVESTIGATED = "Not-Investigated"
    NOT_APPLICABLE = "Not-Applicable"
    IGNORED = "Ignored"
    APPLIED = "Applied"
    NOT_APPLIED = "Not-Applied"


class ThreatResolution(StrEnum):
    NOT_INVESTIGATED = "Not-Investigated"
    NA = "NA"
    MITIGATED = "Mitigated"
    VULNERABLE = "Vulnerable"
    CONDITIONALLY_MITIGATED = "Conditionally-Mitigated"


class MitigationAuditEntry(BaseModel):
    author: str
    evidence: str
    timestamp: datetime


class MitigationState(BaseModel):
    mitigation_id: str
    maturity: MitigationLevel
    resolution: MitigationResolution = MitigationResolution.NOT_INVESTIGATED
    audit_log: List[MitigationAuditEntry] = Field(default_factory=list)


class ThreatAuditEntry(BaseModel):
    author: str
    notes: str
    timestamp: datetime


class ThreatState(BaseModel):
    threat_id: str
    resolution: ThreatResolution
    mitigations: List[MitigationState] = Field(default_factory=list)
    audit_log: List[ThreatAuditEntry] = Field(default_factory=list)


class ThreatHeatMap(BaseModel):
    mitre_version: str = Field(default="2.0.1", description="Version of the EMB3D Threat Model used for this heatmap")
    name: str = Field(..., description="Name of the Project")
    description: str = Field(..., description="Brief description of the Project")

    networking: List[ThreatState] = Field(
        default_factory=list, description="List of networking threats and their states"
    )
    system_software: List[ThreatState] = Field(
        default_factory=list, description="List of system software threats and their states"
    )
    application_software: List[ThreatState] = Field(
        default_factory=list, description="List of application software threats and their states"
    )
    hardware: List[ThreatState] = Field(default_factory=list, description="List of hardware threats and their states")

    def _threat_from_category(self, category: Emb3dCategory, threat_id: str) -> Optional[ThreatState]:
        category_map = {
            Emb3dCategory.NETWORKING: self.networking,
            Emb3dCategory.SYSTEM_SW: self.system_software,
            Emb3dCategory.APP_SW: self.application_software,
            Emb3dCategory.HARDWARE: self.hardware,
        }
        for threat in category_map.get(category, []):
            if threat.threat_id == threat_id:
                return threat
        return None

    def add_audit_entry(
        self,
        category: Emb3dCategory,
        threat_id: str,
        audit_entry: ThreatAuditEntry,
    ) -> None:
        threat = self._threat_from_category(category, threat_id)
        if threat is None:
            raise ValueError(f"Threat with ID {threat_id} not found in category {category}")
        threat.audit_log.append(audit_entry)

    def add_mitigation_audit_entry(
        self,
        category: Emb3dCategory,
        threat_id: str,
        mitigation_id: str,
        audit_entry: MitigationAuditEntry,
    ) -> None:
        threat = self._threat_from_category(category, threat_id)
        if threat is None:
            raise ValueError(f"Threat with ID {threat_id} not found in category {category}")

        mitigation = next((m for m in threat.mitigations if m.mitigation_id == mitigation_id), None)
        if mitigation is None:
            raise ValueError(f"Mitigation with ID {mitigation_id} not found for threat {threat_id}")

        mitigation.audit_log.append(audit_entry)

    def update_mitigation_status(
        self,
        category: Emb3dCategory,
        threat_id: str,
        mitigation_id: str,
        resolution: MitigationResolution,
    ) -> None:
        threat = self._threat_from_category(category, threat_id)
        if threat is None:
            raise ValueError(f"Threat with ID {threat_id} not found in category {category}")

        mitigation = next((m for m in threat.mitigations if m.mitigation_id == mitigation_id), None)
        if mitigation is None:
            raise ValueError(f"Mitigation with ID {mitigation_id} not found for threat {threat_id}")

        mitigation.resolution = resolution

    def update_threat_status(
        self,
        category: Emb3dCategory,
        threat_id: str,
        resolution: ThreatResolution,
    ) -> None:
        threat = self._threat_from_category(category, threat_id)
        if threat is None:
            raise ValueError(f"Threat with ID {threat_id} not found in category {category}")

        threat.resolution = resolution
