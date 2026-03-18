import functools
from pathlib import Path

from google.adk.agents.llm_agent import LlmAgent
from google.adk.agents.readonly_context import ReadonlyContext
from google.adk.models.lite_llm import LiteLlm

from mitre_emb3d.ai._mitre_introduction import MITRE_INTRODUCTION
from mitre_emb3d.ai.config._config import Settings

from ._models import PropertyMapperOutput
from ._prompts import PM_AGENT_SYSTEM_PROMPT


def _instruction_provider(
    ctx: ReadonlyContext,
    extra_context: list[Path],
) -> str:
    extra_context_str = "\n".join([f"### Additional Context:\n{path.read_text()}" for path in extra_context])

    return PM_AGENT_SYSTEM_PROMPT.format(
        MITRE_EMB3D_INTRODUCTION=MITRE_INTRODUCTION,
        EXTRA_CONTEXT=extra_context_str,
    )


class PropertyMapperAgent(LlmAgent):
    def __init__(
        self,
        settings: Settings,
    ) -> None:
        agent_config = settings.property_mapper_agent

        provider = settings.litellm_provider[agent_config.litellm_provider]
        llm = LiteLlm(
            model=provider.model_name,
            **provider.provider_args,
        )

        instruction_provider = functools.partial(
            _instruction_provider,
            extra_context=agent_config.extra_context,
        )

        super().__init__(
            name="property_mapper_agent",
            description="Maps various components & subsystems of an embedded project to MITRE EMB3D Device Properties.",
            model=llm,
            instruction=instruction_provider,
            generate_content_config=agent_config.generate_content,
            output_schema=PropertyMapperOutput,
            output_key="PROPERTY_MAPPER_OUTPUT",
        )

        self._lite_llm = llm

    @property
    def lite_llm(self) -> LiteLlm:
        return self._lite_llm
