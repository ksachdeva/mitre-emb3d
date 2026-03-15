from google.adk.models.lite_llm import LiteLlm
from google.adk.runners import InMemoryRunner
from google.genai import types as genai_types
from rich import print as rprint

from mitre_emb3d.ai.config import Settings

from ._agent import PropertyMapperAgent

_APP_NAME = "property_mapper_app"
_USER_ID = "property_mapper_user"


class PropertyMapper:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._agent = PropertyMapperAgent(
            llm=LiteLlm(
                model=settings.property_mapper_agent.llm.model_name,
                **settings.property_mapper_agent.llm.provider_args,
            ),
            generate_content_config=self._settings.property_mapper_agent.generate_content,
        )

        self._runner = InMemoryRunner(agent=self._agent, app_name=_APP_NAME)

    async def run(self) -> None:
        session = await self._runner.session_service.create_session(
            app_name=_APP_NAME,
            user_id=_USER_ID,
        )

        new_message = "Do your magic!"

        content = genai_types.Content(role="user", parts=[genai_types.Part.from_text(text=new_message)])

        async for event in self._runner.run_async(
            user_id=_USER_ID,
            session_id=session.id,
            new_message=content,
        ):
            if event.content and event.content.parts and event.content.parts[0].text:
                rprint(f"{event.author}:\n {event.content.parts[0].text}")
