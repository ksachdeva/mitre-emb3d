from pathlib import Path
from typing import Any

from google.genai import types as genai_types
from pydantic import BaseModel, Field


class LiteLlmProviderConfig(BaseModel):
    model_name: str
    provider_args: dict[str, Any] = {}


class AgentConfig(BaseModel):
    litellm_provider: str
    # https://googleapis.github.io/python-genai/genai.html#genai.types.GenerateContentConfig
    # Note - not all fields are supported by all models.
    generate_content: genai_types.GenerateContentConfig | None = None


class ProperyMapperAgentConfig(AgentConfig):
    extra_context: list[Path] = Field(
        default_factory=list,
        description="Additional context to provide to the agent",
    )
