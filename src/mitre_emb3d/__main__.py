import json
import logging
import sys
from pathlib import Path
from typing import Annotated, Any, List, Optional, cast

import typer
from pydantic import TypeAdapter
from rich import print as rprint
from rich.console import Console
from rich.markdown import Markdown
from typer import Typer

from mitre_emb3d import __version__
from mitre_emb3d._graph import (
    collect_sub_properties,
    get_mitigation_from_id,
    get_mitigations,
    get_properties_by_category,
    get_subproperties,
    get_threat_from_id,
    get_threat_info_for_mitigation,
    get_threats_by_category,
)
from mitre_emb3d._locations import data_directory
from mitre_emb3d._models import Emb3dCategory, Emb3dPropertyInfo, MitigationWithThreats, ThreatWithMitigations
from mitre_emb3d._stix import load_stix_bunlde
from mitre_emb3d._types import CmdState
from mitre_emb3d.heatmap._cli import heatmap_app
from mitre_emb3d.mcp import build_mcp_server

LOG_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
}


cli_app = Typer(name=f"MITRE EMB3D Client [{__version__}]")
cli_app.add_typer(heatmap_app)


@cli_app.callback()
def main(
    ctx: typer.Context,
    release: Annotated[
        str,
        typer.Option(
            help="2.0.1, 2.0 ...",
        ),
    ] = "2.0.1",
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

    graph = load_stix_bunlde(release)

    ctx.ensure_object(CmdState)
    ctx.obj = CmdState()
    ctx.obj.pprint = pprint
    ctx.obj.graph = graph


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
    G: Any,
    props: list[Emb3dPropertyInfo],
    current_level: int,
    max_level: int,
    indent: int = 0,
) -> None:
    for prop in props:
        rprint(f"{'  ' * indent}- {prop.id}: {prop.name}")
        if current_level < max_level:
            subs = get_subproperties(G, prop)
            if subs:
                _print_properties_pprint(G, subs, current_level + 1, max_level, indent + 1)


@cli_app.command()
def list_properties(
    ctx: typer.Context,
    category: Emb3dCategory,
    level: Annotated[
        int,
        typer.Option(help="Depth of sub-properties to include (1,2,3 ...)"),
    ] = 1,
) -> None:
    """List properties for a certain category"""

    state = cast(CmdState, ctx.obj)
    G = state.graph

    device_properties = get_properties_by_category(G, category)

    if state.pprint:
        _print_properties_pprint(G, device_properties, 1, level)
    else:
        result = collect_sub_properties(G, device_properties, 1, level)
        adapter = TypeAdapter(List[Emb3dPropertyInfo])
        sys.stdout.write(adapter.dump_json(result, indent=None).decode("utf-8"))


@cli_app.command()
def list_threats(ctx: typer.Context, category: Emb3dCategory) -> None:
    "List threats for a certain category"

    state = cast(CmdState, ctx.obj)
    G = state.graph

    threats = get_threats_by_category(G, category)

    if state.pprint:
        for v in threats:
            rprint(f"- {v.id}: {v.name}")
    else:
        result = [{"id": v.id, "name": v.name} for v in threats]
        sys.stdout.write(json.dumps(result, indent=None))


@cli_app.command()
def list_mitigations(ctx: typer.Context, threat_id: str) -> None:
    "List mitigations for a certain threat"

    state = cast(CmdState, ctx.obj)
    G = state.graph

    mitigations = get_mitigations(G, threat_id)

    if state.pprint:
        for m in mitigations:
            rprint(f"- {m.id}: {m.name}")
    else:
        result = [{"id": m.id, "name": m.name} for m in mitigations]
        sys.stdout.write(json.dumps(result, indent=None))


@cli_app.command()
def threat(ctx: typer.Context, threat_id: str) -> None:
    "Threat Information"

    state = cast(CmdState, ctx.obj)
    G = state.graph

    threat = get_threat_from_id(G, threat_id)
    mitigations = get_mitigations(G, threat_id)

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
    G = state.graph

    mitigation = get_mitigation_from_id(G, mitigation_id)
    threat_infos = get_threat_info_for_mitigation(G, mitigation_id)

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
def mcp(
    ctx: typer.Context,
    output_dir: Annotated[
        Optional[Path],
        typer.Option(
            help="Output directory for the generated assets (e.g. heatmap)",
            file_okay=False,
            dir_okay=True,
        ),
    ] = None,
) -> None:
    "Launch the MCP server"

    state = cast(CmdState, ctx.obj)
    G = state.graph

    if output_dir is None:
        output_dir = data_directory()
    else:
        output_dir.mkdir(parents=True, exist_ok=True)

    mcp = build_mcp_server(G, output_dir)
    mcp.run()
