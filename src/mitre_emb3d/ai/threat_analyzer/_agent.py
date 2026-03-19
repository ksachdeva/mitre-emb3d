import functools
from pathlib import Path

from google.adk.agents.llm_agent import LlmAgent
from google.adk.agents.readonly_context import ReadonlyContext
from google.adk.models.lite_llm import LiteLlm

from mitre_emb3d.ai._mitre_introduction import MITRE_INTRODUCTION
from mitre_emb3d.ai.config._config import Settings

from ._models import ThreatAnalyzerOutput
from ._prompts import TA_AGENT_SYSTEM_PROMPT


def _instruction_provider(
    ctx: ReadonlyContext,
    extra_context: list[Path],
) -> str:
    extra_context_str = "\n".join([f"### Additional Context:\n{path.read_text()}" for path in extra_context])

    return TA_AGENT_SYSTEM_PROMPT.format(
        MITRE_EMB3D_INTRODUCTION=MITRE_INTRODUCTION,
        EXTRA_CONTEXT=extra_context_str,
    )


class ThreatAnalyzerAgent(LlmAgent):
    def __init__(
        self,
        settings: Settings,
    ) -> None:
        agent_config = settings.threat_analyzer_agent

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
            name="threat_analyzer_agent",
            description="Analyzes threats for MITRE EMB3D Device Properties based on provided context.",
            model=llm,
            instruction=instruction_provider,
            generate_content_config=agent_config.generate_content,
            output_schema=ThreatAnalyzerOutput,
            output_key=self.analyzer_output_key,
        )

        self._lite_llm = llm

    @property
    def analyzer_output_key(self) -> str:
        return "THREAT_ANALYZER_OUTPUT"

    @property
    def lite_llm(self) -> LiteLlm:
        return self._lite_llm
