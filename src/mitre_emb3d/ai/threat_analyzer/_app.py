import logging
from dataclasses import dataclass
from pathlib import Path

from google.adk.runners import InMemoryRunner
from google.genai import types as genai_types
from rich import print as rprint

from mitre_emb3d._graph import MITREGraph
from mitre_emb3d._models import PropertyId, ThreatInfo, ThreatWithMitigations
from mitre_emb3d.ai.config import Settings
from mitre_emb3d.ai.context.providers import NaiveContextProvider
from mitre_emb3d.ai.property_mapper import read_property_documents
from mitre_emb3d.ai.property_mapper._artifacts import PropertyArtifactDocument
from mitre_emb3d.ai.repo import FsEntry, RepoUnderReview

from ._agent import ThreatAnalyzerAgent
from ._models import ThreatAnalyzerOutput
from ._prompts import TA_AGENT_ANALYSIS_PROMPT

_APP_NAME = "threat_analyzer_app"
_USER_ID = "threat_analyzer_user"

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class _AnalysisTask:
    threat: ThreatWithMitigations
    property_id: str
    property_name: str
    combined_content: str


def _flatten_threats(mitre_graph: MITREGraph) -> list[ThreatInfo]:
    result: list[ThreatInfo] = []
    for category in mitre_graph.get_categories():
        for threat_info in mitre_graph.get_threats_for_category(category):
            result.append(threat_info)
    return result


def _combine_batch(batch: list[FsEntry]) -> str:
    parts: list[str] = []
    for entry in batch:
        parts.append(f"### {entry.path}\n{entry.path.read_text()}")

    return "\n\n".join(parts)


def _build_mitigations_section(threat: ThreatWithMitigations, mitre_graph: MITREGraph) -> str:
    if not threat.mitigations:
        return "No mitigations are associated with this threat."

    mitigations_section = "## Mitigations\n\n"
    for mitigation_info in threat.mitigations:
        mitigation = mitre_graph.get_mitigation_from_id(mitigation_info.id)
        mitigations_section += (
            f"### {mitigation.mitigation_id} [{mitigation.maturity}] - {mitigation.name}\n{mitigation.description}\n\n"
        )

    return mitigations_section


class ThreatAnalyzer:
    def __init__(
        self,
        rur: RepoUnderReview,
        mitre_graph: MITREGraph,
        settings: Settings,
    ) -> None:
        self._mitre_graph = mitre_graph
        self._settings = settings
        self._agent = ThreatAnalyzerAgent(settings=self._settings)
        self._runner = InMemoryRunner(agent=self._agent, app_name=_APP_NAME)
        self._naive_context_provider = NaiveContextProvider(rur)
        self._rur = rur

    async def _run_analysis(self, task: _AnalysisTask) -> ThreatAnalyzerOutput:
        # create a new session
        session = await self._runner.session_service.create_session(app_name=_APP_NAME, user_id=_USER_ID)

        new_message = TA_AGENT_ANALYSIS_PROMPT.format(
            property_id=task.property_id,
            property_name=task.property_name,
            threat_id=task.threat.threat_id,
            threat_description=task.threat.description,
            mitigations_section=_build_mitigations_section(task.threat, self._mitre_graph),
            combined_content=task.combined_content,
        )

        content = genai_types.Content(
            role="user",
            parts=[genai_types.Part.from_text(text=new_message)],
        )

        async for event in self._runner.run_async(
            user_id=_USER_ID,
            session_id=session.id,
            new_message=content,
        ):
            if event.content and event.content.parts and event.content.parts[0].text:
                rprint(f"{event.author}:\n {event.content.parts[0].text}")

        refreshed_session = await self._runner.session_service.get_session(
            app_name=_APP_NAME,
            user_id=_USER_ID,
            session_id=session.id,
        )

        assert refreshed_session is not None, "Session should not be None"

        response = refreshed_session.state.get("THREAT_ANALYZER_OUTPUT", None)

        assert response is not None, "Expected THREAT_ANALYZER_OUTPUT in session state"

        return ThreatAnalyzerOutput.model_validate(response)

    def _filesets_by_device_properties(
        self, prop_documents: dict[PropertyId, PropertyArtifactDocument]
    ) -> dict[PropertyId, list[Path]]:
        prop_to_files: dict[PropertyId, list[Path]] = {prop_id: [] for prop_id in prop_documents.keys()}

        for prop_id, document in prop_documents.items():
            if not document["is_applicable"]:
                continue
            for ev in document["evidence"]:
                file_name = ev["file_name"]
                # need to handle the case where there are multiple pieces of evidence from the same file for the same property
                # we don't want duplicates in the list
                file_path = Path(file_name)
                if file_path not in prop_to_files[prop_id]:
                    prop_to_files[prop_id].append(file_path)

        return prop_to_files

    async def run(self) -> None:
        prop_documents = read_property_documents(self._settings.output_dir)
        file_sets = self._filesets_by_device_properties(prop_documents)

        threats = _flatten_threats(self._mitre_graph)

        for threat in threats:
            _LOGGER.info(f"Analyzing threat {threat.id} - {threat.name} ...")

            # get the properties related to this threat
            related_properties = self._mitre_graph.get_properties_for_threat(threat.id)

            threat_with_mitigations = self._mitre_graph.get_threat_with_mitigations(threat.id)

            for prop in related_properties:
                _LOGGER.info(f"Processing property {prop.id} related to threat {threat.id} ...")
                files_for_prop = file_sets.get(prop.id, [])
                if not files_for_prop:
                    _LOGGER.warning(f"No files found for property {prop.id} related to threat {threat.id}")
                    continue

                context_batches = self._naive_context_provider.get_context(
                    max_tokens=self._settings.threat_analyzer_agent.max_token_per_analysis,
                    file_set=files_for_prop,
                )

                for batch in context_batches:
                    combined_content = _combine_batch(batch)

                    task = _AnalysisTask(
                        threat=threat_with_mitigations,
                        property_id=prop.id,
                        property_name=prop.name,
                        combined_content=combined_content,
                    )

                    analysis_result = await self._run_analysis(task)
                    _LOGGER.info(f"Analysis result for threat {threat.id} - {threat.name}: {analysis_result}")
