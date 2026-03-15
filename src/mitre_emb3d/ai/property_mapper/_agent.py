from google.adk.agents.llm_agent import LlmAgent
from google.adk.models.lite_llm import LiteLlm
from google.genai import types as genai_types


class PropertyMapperAgent(LlmAgent):
    def __init__(
        self,
        llm: LiteLlm,
        generate_content_config: genai_types.GenerateContentConfig | None = None,
    ) -> None:
        self._llm = llm
        self._generate_content_config = generate_content_config

        super().__init__(
            name="property_mapper_agent",
            description="Maps various components & subsystems of an embedded project to MITRE EMB3D Device Properties.",
            model=self._llm,
            instruction="For now just say hello I am not yet ready to do anything",
            generate_content_config=generate_content_config,
        )
