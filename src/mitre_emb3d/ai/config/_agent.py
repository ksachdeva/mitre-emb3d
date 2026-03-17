from pathlib import Path
from typing import Any

from google.genai import types as genai_types
from pydantic import BaseModel, Field

from mitre_emb3d._models import Emb3dCategory, PropertyId


class LiteLlmProviderConfig(BaseModel):
    model_name: str
    provider_args: dict[str, Any] = {}


class AgentConfig(BaseModel):
    litellm_provider: str
    # https://googleapis.github.io/python-genai/genai.html#genai.types.GenerateContentConfig
    # Note - not all fields are supported by all models.
    generate_content: genai_types.GenerateContentConfig | None = None


class ProperyMapperAgentConfig(AgentConfig):
    max_token_per_analysis: int = Field(
        default=8000,
        description="Maximum number of tokens to use for each analysis run",
    )

    extra_context: list[Path] = Field(
        default_factory=list,
        description="Additional context to provide to the agent",
    )

    excluded_categories: list[Emb3dCategory] = Field(
        default_factory=list,
        description="Categories to exclude from consideration by the agent",
    )

    excluded_properties: list[PropertyId] = Field(
        default_factory=list,
        description="Properties to exclude from consideration by the agent",
    )
