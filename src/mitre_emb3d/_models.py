from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any, List, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class MitigationLevel(StrEnum):
    FOUNDATIONAL = "Foundational"
    INTERMEDIATE = "Intermediate"
    LEADING = "Leading"


class Emb3dCategory(StrEnum):
    HARDWARE = "Hardware"
    SYSTEM_SW = "System Software"
    APP_SW = "Application Software"
    NETWORKING = "Networking"


class ObjectType(StrEnum):
    IDENTITY = "identity"
    RELATIONSHIP = "relationship"
    VULNERABILITY = "vulnerability"
    EMB3D_PROPERTY = "x-mitre-emb3d-property"
    COURSE_OF_ACTION = "course-of-action"


class RelationshipType(StrEnum):
    MITIGATES = "mitigates"
    RELATES_TO = "relates-to"
    SUBPROPERTY_OF = "subproperty-of"


class Identity(BaseModel):
    id: str
    type: Literal[ObjectType.IDENTITY]
    name: str
    description: Optional[str] = None


class Relationship(BaseModel):
    id: str
    type: Literal[ObjectType.RELATIONSHIP]
    source_ref: str
    target_ref: str
    relationship_type: RelationshipType

    def graph_props(self) -> dict[str, Any]:
        return {
            "type": str(ObjectType.RELATIONSHIP),
            "relationship_type": str(self.relationship_type),
        }


class Threat(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    type: Literal[ObjectType.VULNERABILITY]
    name: str = Field(..., description="Name of the threat")
    description: str = Field(..., description="Detailed description of the threat")
    cves: str = Field(
        validation_alias="x_mitre_emb3d_threat_CVEs", description="List of CVEs associated with the threat"
    )
    cwes: str = Field(
        validation_alias="x_mitre_emb3d_threat_CWEs", description="List of CWEs associated with the threat"
    )
    evidence: str = Field(
        validation_alias="x_mitre_emb3d_threat_evidence", description="Evidence supporting the threat"
    )
    threat_id: str = Field(validation_alias="x_mitre_emb3d_threat_id", description="Unique identifier for the threat")
    maturity: str = Field(validation_alias="x_mitre_emb3d_threat_maturity", description="Maturity level of the threat")
    category: Emb3dCategory = Field(
        validation_alias="x_mitre_emb3d_threat_category", description="Category of the threat"
    )

    @field_validator("category", mode="before")
    @classmethod
    def normalize_category(cls, v: Any) -> Any:
        if isinstance(v, str):
            for cat in Emb3dCategory:
                if v.lower() == cat.value.lower():
                    return cat.value
        return v

    def graph_id(self) -> str:
        return self.id

    def graph_props(self) -> dict[str, Any]:
        return self.model_dump()

    def display(self) -> str:
        return f""" # {self.name}

{self.description}

**Category:**
{self.category}

**CVEs:**
{self.cves}

**CWEs:**
{self.cwes}

**Evidence:**
{self.evidence}

**Maturity:**
{self.maturity}

"""


class ThreatInfo(BaseModel):
    id: str = Field(..., description="Unique identifier for the threat, prefix is 'TID-', e.g., 'TID-101'")
    name: str = Field(..., description="Name of the threat")


class ThreatWithMitigations(Threat):
    mitigations: List[MitigationInfo] = Field(
        default_factory=list, description="List of mitigations that can address this threat"
    )

    def display(self) -> str:
        base_display = super().display()
        if not self.mitigations:
            return base_display

        mitigations_display = "\n".join(f"- {m.id} - {m.name}\n\n" for m in self.mitigations)
        return f"{base_display}\n---\n ## Mitigations\n\n{mitigations_display}"


class Emb3dPropertyInfo(BaseModel):
    id: str = Field(
        ..., description="Unique identifier for the property, prefix is 'PID-', e.g. 'PID-24', 'PID-241', 'PID-242'"
    )
    name: str = Field(..., description="Name of the property")

    sub_properties: List[Emb3dPropertyInfo] = Field(default_factory=list, description="List of sub-properties")


class Emb3dProperty(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    type: Literal[ObjectType.EMB3D_PROPERTY]
    name: str = Field(..., description="Name of the property")
    category: Emb3dCategory = Field(
        ...,
        description="Category of the property, e.g., 'Hardware', 'System Software', 'Application Software', 'Networking'",
    )
    is_subproperty: Optional[bool] = Field(None, description="Indicates if the property is a sub-property")
    property_id: Optional[str] = Field(
        None,
        validation_alias="x_mitre_emb3d_property_id",
        description="Unique identifier for the property, prefix is 'PID-', e.g., 'PID-24'",
    )

    @field_validator("category", mode="before")
    @classmethod
    def normalize_category(cls, v: Any) -> Any:
        if isinstance(v, str):
            for cat in Emb3dCategory:
                if v.lower() == cat.value.lower():
                    return cat.value
        return v

    @model_validator(mode="after")
    def validate_property_id(self) -> Emb3dProperty:
        if self.is_subproperty is not None and self.property_id is None:
            raise ValueError("x_mitre_emb3d_property_id is required when is_subproperty is set")
        return self

    def graph_id(self) -> str:
        return self.id

    def graph_props(self) -> dict[str, Any]:
        return self.model_dump()


class MitigationInfo(BaseModel):
    id: str = Field(..., description="Unique identifier for the mitigation, prefix is 'MID-', e.g., 'MID-101'")
    name: str = Field(..., description="Name of the mitigation")
    maturity: MitigationLevel = Field(..., description="Maturity level of the mitigation")


class Mitigation(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    type: Literal[ObjectType.COURSE_OF_ACTION]
    name: str = Field(..., description="Name of the mitigation")
    description: str = Field(..., description="Detailed description of the mitigation")
    iec_62443_mappings: str = Field(
        validation_alias="x_mitre_emb3d_mitigation_IEC_62443_mappings", description="Mappings to IEC 62443 standards"
    )
    mitigation_id: str = Field(
        validation_alias="x_mitre_emb3d_mitigation_id",
        description="Unique identifier for the mitigation, prefix is 'MID-', e.g., 'MID-101'",
    )
    maturity: MitigationLevel = Field(
        validation_alias="x_mitre_emb3d_mitigation_maturity", description="Maturity level of the mitigation"
    )
    references: str = Field(
        validation_alias="x_mitre_emb3d_mitigation_references", description="References for the mitigation"
    )

    @field_validator("maturity", mode="before")
    @classmethod
    def normalize_maturity(cls, v: Any) -> Any:
        if isinstance(v, str):
            for ml in MitigationLevel:
                if v.lower() == ml.value.lower():
                    return ml.value
        return v

    def graph_id(self) -> str:
        return self.id

    def graph_props(self) -> dict[str, Any]:
        return self.model_dump()

    def display(self) -> str:
        return f"""# {self.name}

{self.description}

**IEC 62443 Mappings:**
{self.iec_62443_mappings}

**Maturity:**
{self.maturity}

**References:**

{self.references}

"""


class MitigationWithThreats(Mitigation):
    threats: List[ThreatInfo] = Field(
        default_factory=list,
        description="List of threats that this mitigation can address",
    )

    def display(self) -> str:
        base_display = super().display()
        if not self.threats:
            return base_display

        threats_display = "\n".join(f"- {t.id} - {t.name}\n\n" for t in self.threats)
        return f"{base_display}\n---\n ## Mitigates Threats\n\n{threats_display}"


StixObject = Annotated[
    Union[Identity, Relationship, Threat, Emb3dProperty, Mitigation],
    Field(discriminator="type"),
]


class StixBundle(BaseModel):
    type: Literal["bundle"]
    objects: List[StixObject]
