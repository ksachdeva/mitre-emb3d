import asyncio
import os
import sys
from pathlib import Path
from typing import Annotated, List, cast

import networkx as nx
import typer
from pydantic import TypeAdapter
from rich import print as rprint
from typer import Typer

from mitre_emb3d._locations import data_directory
from mitre_emb3d._models import Emb3dCategory
from mitre_emb3d._types import CmdState

from ._models import (
    HeatMapMitigationInfo,
    HeatMapUpdateInfo,
    MitigationResolution,
    ThreatResolution,
    ThreatState,
)
from ._protocols import HeatMapStorage, HeatMapStorageType
from .backend import JSONHeatMapStorage
from .tui._app import MEDApp

heatmap_app = Typer(name="heatmap", help="HeatMap related commands")


def _get_storage(project_name: str, heatmap_storage_type: HeatMapStorageType, G: nx.DiGraph) -> HeatMapStorage:
    assert heatmap_storage_type == HeatMapStorageType.JSON, "Only JSON heatmap storage is supported for the MCP server"

    storage_dir_from_env = os.getenv("MITRE_EMB3D_HEATMAP_JSON_STORAGE_DIR", None)

    if storage_dir_from_env is None:
        storage_dir = data_directory()  # type: ignore
    else:
        storage_dir = Path(storage_dir_from_env)
        storage_dir.mkdir(parents=True, exist_ok=True)

    storage = JSONHeatMapStorage(G, storage_dir)

    async def _run() -> bool:
        return await storage.project_exists(project_name)

    project_exists = asyncio.run(_run())

    if not project_exists:
        rprint(
            f"[red]Error:[/red] Heatmap storage not found for project {project_name}. Please run 'heatmap init' command first."
        )
        sys.exit(1)

    return storage


@heatmap_app.command(name="init")
def initialize(ctx: typer.Context, project_name: str, description: str) -> None:
    """Initialize a heatmap JSON file with all threats set to NOT_INVESTIGATED."""
    state = cast(CmdState, ctx.obj)
    storage = _get_storage(project_name, state.heatmap_storage_type, state.graph)

    async def _run() -> None:
        await storage.initialize(project_name, description)

    asyncio.run(_run())


@heatmap_app.command(name="read")
def read(
    ctx: typer.Context,
    project_name: str,
    category: Annotated[Emb3dCategory, typer.Argument(help="Category to list threat states for")],
) -> None:
    """List the threat states for the given category."""
    state = cast(CmdState, ctx.obj)
    storage = _get_storage(project_name, state.heatmap_storage_type, state.graph)

    async def _run() -> list[ThreatState]:
        threats = await storage.read_entries(project_name, category)
        return threats

    threats = asyncio.run(_run())

    adapter = TypeAdapter(List[ThreatState])

    sys.stdout.write(adapter.dump_json(threats, indent=0).decode("utf-8"))


@heatmap_app.command(name="update-threat-status")
def update_threat_status(
    ctx: typer.Context,
    project_name: str,
    category: Annotated[Emb3dCategory, typer.Argument(help="Category to update the threat state for")],
    threat_id: Annotated[
        str,
        typer.Argument(help="Threat ID to update (e.g. TID-123)"),
    ],
    threat_resolution: Annotated[ThreatResolution, typer.Option("--tr", help="Threat resolution state")],
) -> None:
    """Update the heatmap file with the latest threat states from the graph."""

    state = cast(CmdState, ctx.obj)
    storage = _get_storage(project_name, state.heatmap_storage_type, state.graph)

    async def _run() -> None:
        await storage.update_entry(
            project_name,
            category,
            threat_id,
            HeatMapUpdateInfo(resolution=threat_resolution),
        )

    asyncio.run(_run())


@heatmap_app.command(name="update-mitigation-status")
def update_mitigation_status(
    ctx: typer.Context,
    project_name: str,
    category: Annotated[Emb3dCategory, typer.Argument(help="Category to update the threat state for")],
    threat_id: Annotated[
        str,
        typer.Argument(help="Threat ID to update (e.g. TID-123)"),
    ],
    mitigation_id: Annotated[
        str,
        typer.Argument(help="Mitigation ID to update (e.g. MID-123)"),
    ],
    mitigation_resolution: Annotated[MitigationResolution, typer.Option("--mr", help="Mitigation resolution state")],
) -> None:
    """Update the heatmap file with the latest threat states from the graph."""

    state = cast(CmdState, ctx.obj)
    storage = _get_storage(project_name, state.heatmap_storage_type, state.graph)

    async def _run() -> None:
        await storage.update_entry(
            project_name,
            category,
            threat_id,
            HeatMapUpdateInfo(
                mitigation_infos=[
                    HeatMapMitigationInfo(
                        mitigation_id=mitigation_id,
                        resolution=mitigation_resolution,
                    )
                ]
            ),
        )

    asyncio.run(_run())


@heatmap_app.command(name="tui")
def tui(ctx: typer.Context, project_name: str) -> None:
    "Launch the TUI heatmap viewer & editor"

    state = cast(CmdState, ctx.obj)
    storage = _get_storage(project_name, state.heatmap_storage_type, state.graph)

    app = MEDApp(state.graph, project_name, storage)
    app.run()
