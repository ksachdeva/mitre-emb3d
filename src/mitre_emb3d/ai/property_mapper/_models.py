from pydantic import BaseModel, Field


class Evidence(BaseModel):
    file_name: str = Field(..., description="The name of the file that contains evidence for the property.")
    code_snippet: str = Field(
        ...,
        description="A code snippet from the file that provides evidence for the property's relevance.",
    )


class PropertyMapperOutput(BaseModel):
    property_id: str = Field(..., description="The ID of the MITRE EMB3D Device Property being analyzed.")
    is_relevant: bool = Field(
        ..., description="Whether the property is relevant to the project based on the provided context."
    )
    evidence: list[Evidence] = Field(
        default_factory=list,
        description="A list of evidence supporting the relevance of the property to the project. Only included if is_relevant is true.",
    )
