from pydantic import BaseModel, Field


class MitigationAnalysis(BaseModel):
    mitigation_id: str = Field(..., description="The ID of the MITRE EMB3D Device Mitigation being analyzed.")
    file_name: str = Field(
        ...,
        description="The name of the file on which the threat evidence was found.",
    )
    is_applied: bool = Field(..., description="Whether the mitigation has been applied based on the provided context.")
    explanation: str = Field(
        ...,
        description="An explanation of why the mitigation is or isn't applied based on the provided context.",
    )


class ThreatAnalyzerOutput(BaseModel):
    threat_id: str = Field(..., description="The ID of the MITRE EMB3D Device Threat being analyzed.")
    property_id: str = Field(..., description="The ID of the MITRE EMB3D Device Property being analyzed.")
    mitigation_info: list[MitigationAnalysis] = Field(
        default_factory=list,
        description="A list of evidence supporting the relevance of the mitigation to the project. Only included if is_relevant is true.",
    )
