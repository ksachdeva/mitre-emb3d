from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any, List, Literal, Optional, Union

from pydantic import BaseModel, Field, model_validator


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
            "object_type": str(ObjectType.RELATIONSHIP),
            "relationship_type": str(self.relationship_type),
        }


class Vulnerability(BaseModel):
    id: str
    type: Literal[ObjectType.VULNERABILITY]
    name: str
    description: str
    x_mitre_emb3d_threat_CVEs: str
    x_mitre_emb3d_threat_CWEs: str
    x_mitre_emb3d_threat_evidence: str
    x_mitre_emb3d_threat_id: str
    x_mitre_emb3d_threat_maturity: str
    x_mitre_emb3d_threat_category: str

    def graph_id(self) -> str:
        return self.id

    def graph_props(self) -> dict[str, Any]:
        return {
            "object_type": str(ObjectType.VULNERABILITY),
            "name": self.name,
            "id": self.id,
            "description": self.description,
            "x_mitre_emb3d_threat_CVEs": self.x_mitre_emb3d_threat_CVEs,
            "x_mitre_emb3d_threat_CWEs": self.x_mitre_emb3d_threat_CWEs,
            "x_mitre_emb3d_threat_evidence": self.x_mitre_emb3d_threat_evidence,
            "x_mitre_emb3d_threat_id": self.x_mitre_emb3d_threat_id,
            "x_mitre_emb3d_threat_maturity": self.x_mitre_emb3d_threat_maturity,
            "x_mitre_emb3d_threat_category": self.x_mitre_emb3d_threat_category,
        }


class Emb3dProperty(BaseModel):
    id: str
    type: Literal[ObjectType.EMB3D_PROPERTY]
    name: str
    category: str
    is_subproperty: Optional[bool] = None
    x_mitre_emb3d_property_id: Optional[str] = None

    @model_validator(mode="after")
    def validate_property_id(self) -> Emb3dProperty:
        if self.is_subproperty is not None and self.x_mitre_emb3d_property_id is None:
            raise ValueError("x_mitre_emb3d_property_id is required when is_subproperty is set")
        return self

    def graph_id(self) -> str:
        return self.id

    def graph_props(self) -> dict[str, Any]:
        result = {
            "object_type": str(ObjectType.EMB3D_PROPERTY),
            "id": self.id,
            "name": self.name,
            "category": self.category,
        }

        if self.is_subproperty is not None:
            result["is_subproperty"] = str(self.is_subproperty)

        if self.x_mitre_emb3d_property_id is not None:
            result["x_mitre_emb3d_property_id"] = self.x_mitre_emb3d_property_id

        return result


class CourseOfAction(BaseModel):
    id: str
    type: Literal[ObjectType.COURSE_OF_ACTION]
    name: str
    description: str
    x_mitre_emb3d_mitigation_IEC_62443_mappings: str
    x_mitre_emb3d_mitigation_id: str
    x_mitre_emb3d_mitigation_maturity: str
    x_mitre_emb3d_mitigation_references: str

    def graph_id(self) -> str:
        return self.id

    def graph_props(self) -> dict[str, Any]:
        return {
            "object_type": str(ObjectType.COURSE_OF_ACTION),
            "name": self.name,
            "id": self.id,
            "description": self.description,
            "x_mitre_emb3d_mitigation_IEC_62443_mappings": self.x_mitre_emb3d_mitigation_IEC_62443_mappings,
            "x_mitre_emb3d_mitigation_id": self.x_mitre_emb3d_mitigation_id,
            "x_mitre_emb3d_mitigation_maturity": self.x_mitre_emb3d_mitigation_maturity,
            "x_mitre_emb3d_mitigation_references": self.x_mitre_emb3d_mitigation_references,
        }


StixObject = Annotated[
    Union[Identity, Relationship, Vulnerability, Emb3dProperty, CourseOfAction],
    Field(discriminator="type"),
]


class StixBundle(BaseModel):
    type: Literal["bundle"]
    objects: List[StixObject]
