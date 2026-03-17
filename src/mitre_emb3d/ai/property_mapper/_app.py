import logging
from dataclasses import dataclass

from google.adk.runners import InMemoryRunner
from google.genai import types as genai_types
from rich import print as rprint

from mitre_emb3d._graph import MITREGraph
from mitre_emb3d._models import Emb3dCategory, Emb3dPropertyInfo, PropertyId
from mitre_emb3d.ai.config import Settings
from mitre_emb3d.ai.context.providers import NaiveContextProvider
from mitre_emb3d.ai.repo import FsEntry, RepoUnderReview

from ._agent import PropertyMapperAgent
from ._prompt import PM_AGENT_ANALYSIS_PROMPT

_APP_NAME = "property_mapper_app"
_USER_ID = "property_mapper_user"

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class _AnalysisTask:
    category: Emb3dCategory
    property_info: tuple[PropertyId, str]
    combined_content: str


def _flatten_properties(properties: list[Emb3dPropertyInfo]) -> list[tuple[PropertyId, str]]:
    result: list[tuple[PropertyId, str]] = []
    stack = list(properties)
    while stack:
        prop = stack.pop()
        result.append((prop.id, prop.name))
        stack.extend(prop.sub_properties)
    return result


def _properties_for_categories(mitre_graph: MITREGraph) -> dict[Emb3dCategory, list[tuple[PropertyId, str]]]:
    categories = mitre_graph.get_categories()
    result: dict[Emb3dCategory, list[tuple[PropertyId, str]]] = {}

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

    async def _run_analysis(self, task: _AnalysisTask) -> None:
        # create a new session
        session = await self._runner.session_service.create_session(app_name=_APP_NAME, user_id=_USER_ID)

        new_message = PM_AGENT_ANALYSIS_PROMPT.format(
            category=task.category,
            property_id=task.property_info[0],
            property_name=task.property_info[1],
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

            if event.is_final_response():
                rprint("Final response received, ending analysis for this task.")
                break

        refreshed_session = await self._runner.session_service.get_session(
            app_name=_APP_NAME,
            user_id=_USER_ID,
            session_id=session.id,
        )

        assert refreshed_session is not None, "Session should not be None"

        response = refreshed_session.state.get("PROPERTY_MAPPER_OUTPUT", None)

        rprint(response)

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
            for property_info in properties:
                tasks.append(
                    _AnalysisTask(
                        category=category,
                        property_info=property_info,
                        combined_content=combined_content,
                    )
                )
        return tasks

    async def run(self) -> None:
        batches = self._naive_context_provider.get_context(
            self._settings.property_mapper_agent.max_token_per_analysis,
        )

        for batch in batches:
            combined_content = self._combine_batch(batch)
            tasks = self._tasks_for_batch(combined_content)

            for _, task in enumerate(tasks):
                await self._run_analysis(task)
