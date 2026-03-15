import logging
import os
import sys
from pathlib import Path
from typing import Annotated, List, cast

import typer
from pydantic import TypeAdapter
from rich import print as rprint
from rich.console import Console
from rich.markdown import Markdown
from typer import Typer

from mitre_emb3d import __version__
from mitre_emb3d._graph import MITREGraph
from mitre_emb3d._locations import data_directory
from mitre_emb3d._models import (
    Emb3dCategory,
    Emb3dPropertyInfo,
    MitigationInfo,
    MitigationWithThreats,
    ThreatInfo,
    ThreatWithMitigations,
)
from mitre_emb3d._stix import make_mitre_graph
from mitre_emb3d._types import CmdState
from mitre_emb3d.ai._cli import ai_app
from mitre_emb3d.heatmap import HeatMapStorageType
from mitre_emb3d.heatmap._cli import heatmap_app
from mitre_emb3d.heatmap.backend import JSONHeatMapStorage
from mitre_emb3d.mcp import build_mcp_server

LOG_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
}


cli_app = Typer(name=f"MITRE EMB3D CLI [{__version__}]")
cli_app.add_typer(heatmap_app)
cli_app.add_typer(ai_app)


def version_callback(value: bool) -> None:
    if value:
        rprint(f"MITRE EMB3D CLI Version: {__version__}")
        raise typer.Exit()


@cli_app.callback()
def main(
    ctx: typer.Context,
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            callback=version_callback,
            is_eager=True,
            help="Show the version of CLI and exit",
        ),
    ] = None,
    release: Annotated[
        str,
        typer.Option(
            help="2.0.1, 2.0 ...",
        ),
    ] = "2.0.1",
    heatmap_storage: Annotated[
        HeatMapStorageType,
        typer.Option(
            help="Storage type for heatmaps (e.g. json)",
        ),
    ] = HeatMapStorageType.JSON,
    loglevel: Annotated[
        str,
        typer.Option(
            "--loglevel",
            "-l",
            help="Set the logging level (debug, info, warning, error, critical)",
        ),
    ] = "warning",
    pprint: Annotated[bool, typer.Option(help="Whether to pretty-print the output (e.g. JSON lists)")] = False,
) -> None:
    logging.basicConfig(level=LOG_LEVELS.get(loglevel, logging.WARNING))
    logging.getLogger("mitre_emb3d").setLevel(LOG_LEVELS.get(loglevel, logging.WARNING))

    graph = make_mitre_graph(release)

    ctx.ensure_object(CmdState)
    ctx.obj = CmdState()
    ctx.obj.pprint = pprint
    ctx.obj.graph = graph
    ctx.obj.heatmap_storage_type = heatmap_storage


@cli_app.command()
def list_categories(ctx: typer.Context) -> None:
    "List the categories"

    state = cast(CmdState, ctx.obj)

    the_categories: List[str] = [
        Emb3dCategory.HARDWARE,
        Emb3dCategory.SYSTEM_SW,
        Emb3dCategory.APP_SW,
        Emb3dCategory.NETWORKING,
    ]

    adapter = TypeAdapter(List[str])

    if state.pprint:
        console = Console()
        category_list = "\n".join(f"- {c}" for c in the_categories)
        md_categories = Markdown(f"\n ## Categories\n\n{category_list}")
        console.print(md_categories)
    else:
        sys.stdout.write(adapter.dump_json(the_categories, indent=0).decode("utf-8"))


def _print_properties_pprint(
    mitre_graph: MITREGraph,
    props: list[Emb3dPropertyInfo],
    current_level: int,
    max_level: int,
    indent: int = 0,
) -> None:
    for prop in props:
        rprint(f"{'  ' * indent}- {prop.id}: {prop.name}")
        if current_level < max_level:
            subs = mitre_graph.get_subproperties(prop)
            if subs:
                _print_properties_pprint(mitre_graph, subs, current_level + 1, max_level, indent + 1)


@cli_app.command()
def list_properties_for_category(
    ctx: typer.Context,
    category: Emb3dCategory,
    level: Annotated[
        int,
        typer.Option(help="Depth of sub-properties to include (1,2,3 ...)"),
    ] = 1,
) -> None:
    """List properties for a certain category"""

    state = cast(CmdState, ctx.obj)
    mitre_graph = state.graph

    device_properties = mitre_graph.get_properties_for_category(category)

    if state.pprint:
        _print_properties_pprint(mitre_graph, device_properties, 1, level)
    else:
        result = mitre_graph.collect_sub_properties(device_properties, 1, level)
        adapter = TypeAdapter(List[Emb3dPropertyInfo])
        sys.stdout.write(adapter.dump_json(result, indent=None).decode("utf-8"))


@cli_app.command()
def list_properties_for_threat(ctx: typer.Context, threat_id: str) -> None:
    "List properties for a certain threat"

    state = cast(CmdState, ctx.obj)
    mitre_graph = state.graph

    properties = mitre_graph.get_properties_for_threat(threat_id)

    if state.pprint:
        for v in properties:
            rprint(f"- {v.id}: {v.name}")
    else:
        adapter = TypeAdapter(List[Emb3dPropertyInfo])
        sys.stdout.write(adapter.dump_json(properties, indent=None).decode("utf-8"))


@cli_app.command()
def list_threats_for_category(ctx: typer.Context, category: Emb3dCategory) -> None:
    "List threats for a certain category"

    state = cast(CmdState, ctx.obj)
    mitre_graph = state.graph

    threats = mitre_graph.get_threats_for_category(category)

    if state.pprint:
        for v in threats:
            rprint(f"- {v.id}: {v.name}")
    else:
        adapter = TypeAdapter(List[ThreatInfo])
        sys.stdout.write(adapter.dump_json(threats, indent=None).decode("utf-8"))


@cli_app.command()
def list_threats_for_property(ctx: typer.Context, property_id: str) -> None:
    "List threats for a certain device property"

    state = cast(CmdState, ctx.obj)
    mitre_graph = state.graph

    threats = mitre_graph.get_threats_for_property(property_id)

    if state.pprint:
        for v in threats:
            rprint(f"- {v.id}: {v.name}")
    else:
        adapter = TypeAdapter(List[ThreatInfo])
        sys.stdout.write(adapter.dump_json(threats, indent=None).decode("utf-8"))


@cli_app.command()
def list_mitigations(ctx: typer.Context, threat_id: str) -> None:
    "List mitigations for a certain threat"

    state = cast(CmdState, ctx.obj)
    mitre_graph = state.graph

    mitigations = mitre_graph.get_mitigations(threat_id)

    if state.pprint:
        for m in mitigations:
            rprint(f"- {m.id}: {m.name}")
    else:
        adapter = TypeAdapter(List[MitigationInfo])
        sys.stdout.write(adapter.dump_json(mitigations, indent=None).decode("utf-8"))


@cli_app.command()
def threat(ctx: typer.Context, threat_id: str) -> None:
    "Threat Information"

    state = cast(CmdState, ctx.obj)
    mitre_graph = state.graph

    threat = mitre_graph.get_threat_from_id(threat_id)
    mitigations = mitre_graph.get_mitigations(threat_id)

    threat_with_mitigations = ThreatWithMitigations(**threat.model_dump(), mitigations=mitigations)

    if state.pprint:
        console = Console()
        md = Markdown(threat_with_mitigations.display())
        console.print(md)
    else:
        dump = threat_with_mitigations.model_dump_json(exclude_none=True, exclude={"id"})
        sys.stdout.write(dump)


@cli_app.command()
def mitigation(ctx: typer.Context, mitigation_id: str) -> None:
    "Mitigation Information"

    state = cast(CmdState, ctx.obj)
    mitre_graph = state.graph

    mitigation = mitre_graph.get_mitigation_from_id(mitigation_id)
    threat_infos = mitre_graph.get_threat_info_for_mitigation(mitigation_id)

    mitigation_with_threats = MitigationWithThreats(
        **mitigation.model_dump(),
        threats=threat_infos,
    )

    if state.pprint:
        console = Console()
        md = Markdown(mitigation_with_threats.display())
        console.print(md)
    else:
        dump = mitigation_with_threats.model_dump_json(exclude_none=True, exclude={"id"}, indent=2)
        sys.stdout.write(dump)


@cli_app.command()
def mcp(ctx: typer.Context) -> None:
    "Launch the MCP server"

    state = cast(CmdState, ctx.obj)
    mitre_graph = state.graph

    assert state.heatmap_storage_type == HeatMapStorageType.JSON, (
        "Only JSON heatmap storage is supported for the MCP server"
    )

    storage_dir_from_env = os.getenv("MITRE_EMB3D_HEATMAP_JSON_STORAGE_DIR", None)

    if storage_dir_from_env is None:
        storage_dir = data_directory()  # type: ignore
    else:
        storage_dir = Path(storage_dir_from_env)
        storage_dir.mkdir(parents=True, exist_ok=True)

    storage = JSONHeatMapStorage(mitre_graph, storage_dir)

    mcp = build_mcp_server(mitre_graph, storage)
    mcp.run()
