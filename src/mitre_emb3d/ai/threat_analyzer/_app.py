import asyncio
import logging
from dataclasses import dataclass
from pathlib import Path

from google.adk.runners import InMemoryRunner
from google.genai import types as genai_types
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from mitre_emb3d._graph import MITREGraph
from mitre_emb3d._models import PropertyId, ThreatId, ThreatInfo, ThreatWithMitigations
from mitre_emb3d.ai.config import Settings
from mitre_emb3d.ai.context.providers import NaiveContextProvider
from mitre_emb3d.ai.property_mapper import read_property_documents
from mitre_emb3d.ai.property_mapper._artifacts import PropertyArtifactDocument
from mitre_emb3d.ai.repo import FsEntry, RepoUnderReview

from ._agent import ThreatAnalyzerAgent
from ._artifacts import write_threat_documents
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
        self._console = Console()
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
                _LOGGER.debug(f"{event.author}:\n {event.content.parts[0].text}")

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

    def _merge_results(
        self,
        existing: dict[PropertyId, ThreatAnalyzerOutput],
        new_results: list[ThreatAnalyzerOutput],
    ) -> dict[PropertyId, ThreatAnalyzerOutput]:
        merged = dict(existing)
        for result in new_results:
            pid = result.property_id
            prev = merged.get(pid)
            if prev is None:
                merged[pid] = result
                continue

            # merge mitigation_info: deduplicate by (mitigation_id, file_name)
            seen = {(m.mitigation_id, m.file_name) for m in prev.mitigation_info}
            for m in result.mitigation_info:
                if (m.mitigation_id, m.file_name) not in seen:
                    prev.mitigation_info.append(m)
                    seen.add((m.mitigation_id, m.file_name))

        return merged

    async def run(self) -> None:
        prop_documents = read_property_documents(self._settings.output_dir)
        file_sets = self._filesets_by_device_properties(prop_documents)

        threats = _flatten_threats(self._mitre_graph)

        accumulated: dict[ThreatId, dict[PropertyId, ThreatAnalyzerOutput]] = {}

        sem = asyncio.Semaphore(self._settings.threat_analyzer_agent.number_of_concurrent_analysis)

        async def _guarded_analysis(task: _AnalysisTask) -> ThreatAnalyzerOutput:
            async with sem:
                return await self._run_analysis(task)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=self._console,
        ) as progress:
            task_id = progress.add_task("Analyzing threats...", total=len(threats))

            for threat in threats:
                progress.update(task_id, description=f"[cyan]{threat.id}[/] {threat.name}")
                _LOGGER.info(f"Analyzing threat {threat.id} - {threat.name} ...")

                related_properties = self._mitre_graph.get_properties_for_threat(threat.id)
                threat_with_mitigations = self._mitre_graph.get_threat_with_mitigations(threat.id)

                # collect all tasks across properties and batches for this threat
                all_tasks: list[_AnalysisTask] = []

                for prop in related_properties:
                    _LOGGER.info(f"Processing property {prop.id} related to threat {threat.id} ...")
                    files_for_prop = file_sets.get(prop.id, [])
                    if not files_for_prop:
                        # absence of files indicate that propery was deemed not applicable by the property mapper,
                        # so we should skip analysis for this property
                        continue

                    context_batches = self._naive_context_provider.get_context(
                        max_tokens=self._settings.threat_analyzer_agent.max_token_per_analysis,
                        file_set=files_for_prop,
                    )

                    for batch in context_batches:
                        combined_content = _combine_batch(batch)
                        all_tasks.append(
                            _AnalysisTask(
                                threat=threat_with_mitigations,
                                property_id=prop.id,
                                property_name=prop.name,
                                combined_content=combined_content,
                            )
                        )

                if not all_tasks:
                    _LOGGER.info(f"No analysis tasks for threat {threat.id}, skipping.")
                    progress.advance(task_id)
                    continue

                # run all tasks for this threat concurrently (bounded by semaphore)
                async with asyncio.TaskGroup() as tg:
                    futures = [tg.create_task(_guarded_analysis(t)) for t in all_tasks]

                _LOGGER.info(f"All analyses for threat {threat.id} completed, merging results ...")

                results = [f.result() for f in futures]

                # merge results into per-property accumulator for this threat
                threat_acc = accumulated.get(threat.id, {})
                accumulated[threat.id] = self._merge_results(threat_acc, results)

                # flush after each threat
                write_threat_documents(
                    accumulated,
                    self._mitre_graph,
                    self._settings.output_dir,
                    self._rur.head_commit,
                    self._agent.lite_llm.model,
                )

                progress.advance(task_id)
