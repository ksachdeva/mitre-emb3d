from typing import Any

from google.genai import types as genai_types
from pydantic import BaseModel


class LiteLlmProviderConfig(BaseModel):
    model_name: str
    provider_args: dict[str, Any] = {}


class AgentConfig(BaseModel):
    litellm_provider: str
    # https://googleapis.github.io/python-genai/genai.html#genai.types.GenerateContentConfig
    # Note - not all fields are supported by all models.
    generate_content: genai_types.GenerateContentConfig | None = None
