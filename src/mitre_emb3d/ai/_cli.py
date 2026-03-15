import asyncio
from pathlib import Path
from typing import Annotated, cast

import typer
from typer import Typer

from mitre_emb3d._types import CmdState

from .config import Settings
from .property_mapper import PropertyMapper

ai_app = Typer(name="ai", help="AI related commands")


@ai_app.callback()
def ai(
    ctx: typer.Context,
    repo: Annotated[Path, typer.Option(help="Path to the repository", dir_okay=True, file_okay=False, exists=True)],
    config: Annotated[Path, typer.Option(help="Path to the config file", dir_okay=False, file_okay=True, exists=True)],
) -> None:
    """AI related commands for MITRE EMB3D"""
    state = cast(CmdState, ctx.obj)
    state.ai.repo = repo

    Settings._toml_file = config
    state.ai.settings = Settings()  # type: ignore


@ai_app.command()
def map_properties(ctx: typer.Context) -> None:
    """Map the repository to the MITRE EMB3D Device Properties"""
    state = cast(CmdState, ctx.obj)

    mapper = PropertyMapper(state.ai.settings)

    async def _run() -> None:
        await mapper.run()

    asyncio.run(_run())
