import asyncio
import logging
from dataclasses import dataclass
from typing import NamedTuple

from google.adk.runners import InMemoryRunner
from google.genai import types as genai_types
from rich import print as rprint

from mitre_emb3d._graph import MITREGraph
from mitre_emb3d._models import Emb3dCategory, Emb3dPropertyInfo, PropertyId
from mitre_emb3d.ai.config import Settings
from mitre_emb3d.ai.context.providers import NaiveContextProvider
from mitre_emb3d.ai.repo import FsEntry, RepoUnderReview

from ._agent import PropertyMapperAgent
from ._artifacts import write_property_documents
from ._models import PropertyMapperOutput
from ._prompts import PM_AGENT_ANALYSIS_PROMPT

_APP_NAME = "property_mapper_app"
_USER_ID = "property_mapper_user"

_LOGGER = logging.getLogger(__name__)


class _PropertyIdName(NamedTuple):
    property_id: PropertyId
    property_name: str


@dataclass(frozen=True)
class _AnalysisTask:
    category: Emb3dCategory
    property_info: _PropertyIdName
    combined_content: str


def _flatten_properties(properties: list[Emb3dPropertyInfo]) -> list[_PropertyIdName]:
    result: list[_PropertyIdName] = []
    stack = list(properties)
    while stack:
        prop = stack.pop()
        result.append(_PropertyIdName(property_id=prop.id, property_name=prop.name))
        stack.extend(prop.sub_properties)
    return result


def _properties_for_categories(mitre_graph: MITREGraph) -> dict[Emb3dCategory, list[_PropertyIdName]]:
    categories = mitre_graph.get_categories()
    result: dict[Emb3dCategory, list[_PropertyIdName]] = {}

    for category in categories:
        top_level_properties = mitre_graph.get_properties_for_category(category)
        device_properties = mitre_graph.collect_sub_properties(top_level_properties, 1, 7)
        result[category] = _flatten_properties(device_properties)
    return result


class PropertyMapper:
    def __init__(
        self,
        rur: RepoUnderReview,
        mitre_graph: MITREGraph,
        settings: Settings,
    ) -> None:
        self._mitre_graph = mitre_graph
        self._settings = settings
        self._agent = PropertyMapperAgent(settings=self._settings)
        self._runner = InMemoryRunner(agent=self._agent, app_name=_APP_NAME)
        self._naive_context_provider = NaiveContextProvider(rur)
        self._properties_by_category = _properties_for_categories(self._mitre_graph)
        self._rur = rur

    async def _run_analysis(self, task: _AnalysisTask) -> PropertyMapperOutput:
        # create a new session
        session = await self._runner.session_service.create_session(app_name=_APP_NAME, user_id=_USER_ID)

        new_message = PM_AGENT_ANALYSIS_PROMPT.format(
            category=task.category,
            property_id=task.property_info.property_id,
            property_name=task.property_info.property_name,
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

        response = refreshed_session.state.get("PROPERTY_MAPPER_OUTPUT", None)

        assert response is not None, "Expected PROPERTY_MAPPER_OUTPUT in session state"

        return PropertyMapperOutput.model_validate(response)

    @staticmethod
    def _combine_batch(batch: list[FsEntry]) -> str:
        parts: list[str] = []
        for entry in batch:
            _LOGGER.info(f"Adding {entry.path} to combined content ...")
            parts.append(f"### {entry.path}\n{entry.path.read_text()}")

        return "\n\n".join(parts)

    def _tasks_for_batch(self, combined_content: str) -> list[_AnalysisTask]:
        tasks: list[_AnalysisTask] = []
        for category, properties in self._properties_by_category.items():
            if category in self._settings.property_mapper_agent.excluded_categories:
                _LOGGER.info(f"Skipping category {category} ...")
                continue
            for property_info in properties:
                if property_info.property_id in self._settings.property_mapper_agent.excluded_properties:
                    _LOGGER.info(f"Skipping {property_info.property_id} ...")
                    continue
                tasks.append(
                    _AnalysisTask(
                        category=category,
                        property_info=property_info,
                        combined_content=combined_content,
                    )
                )
        return tasks

    def _merge_results(self, results: list[PropertyMapperOutput]) -> dict[PropertyId, PropertyMapperOutput]:
        merged: dict[PropertyId, PropertyMapperOutput] = {}
        for result in results:
            existing = merged.get(result.property_id, None)
            if existing is None:
                merged[result.property_id] = result
                continue

            if not result.is_relevant:
                continue

            existing.is_relevant = True
            seen = {(e.file_name, e.code_snippet) for e in existing.evidence}
            for ev in result.evidence:
                if (ev.file_name, ev.code_snippet) not in seen:
                    existing.evidence.append(ev)
                    seen.add((ev.file_name, ev.code_snippet))

        return merged

    async def run(self) -> None:
        batches = self._naive_context_provider.get_context(
            self._settings.property_mapper_agent.max_token_per_analysis,
        )
        accumulated: dict[PropertyId, PropertyMapperOutput] = {}

        sem = asyncio.Semaphore(self._settings.property_mapper_agent.number_of_concurrent_analysis)

        async def _guarded_analysis(task: _AnalysisTask) -> PropertyMapperOutput:
            async with sem:
                return await self._run_analysis(task)

        for batch in batches:
            # process one batch at a time, but run analyses for properties in parallel
            combined_content = self._combine_batch(batch)
            tasks = self._tasks_for_batch(combined_content)

            # run analyses for all properties in this batch in parallel, but limit concurrency with a semaphore
            async with asyncio.TaskGroup() as tg:
                futures = [tg.create_task(_guarded_analysis(t)) for t in tasks]

            _LOGGER.info("All analyses for this batch completed, merging results ...")

            results = [f.result() for f in futures]
            batch_merged = self._merge_results(results)

            # merge batch results into the running accumulator
            accumulated = self._merge_results(list(accumulated.values()) + list(batch_merged.values()))

            # now dump them in the file system
            write_property_documents(
                accumulated,
                self._mitre_graph,
                self._settings.output_dir,
                self._rur.head_commit,
                self._agent.lite_llm.model,
            )
