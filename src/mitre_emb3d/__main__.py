import json
import logging
import sys
from pathlib import Path
from typing import Annotated, Any, List, cast

import typer
from pydantic import TypeAdapter
from rich import print as rprint
from typer import Typer

from mitre_emb3d import __version__
from mitre_emb3d._doc_loaders import download_release
from mitre_emb3d._graph import (
    build_split_graph,
    get_mitigations,
    get_properties_by_category,
    get_subproperties,
    get_threats_by_category,
    write_graphml,
)
from mitre_emb3d._heatmap import heatmap_app
from mitre_emb3d._locations import cache_directory
from mitre_emb3d._models import Emb3dCategory
from mitre_emb3d._models import StixBundle as ST
from mitre_emb3d._types import CmdState

_LOGGER = logging.getLogger(__name__)

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

    # cache file_name
    file_name = cache_directory().joinpath(f"emb3d-stix-{release}.json")

    if not file_name.exists():
        download_release(release, file_name)

    _LOGGER.info(f"Loading emb3d-stix-{release}.json from cache ...")
    bundle_doc = ST.model_validate_json(file_name.read_text())

    ctx.ensure_object(CmdState)
    ctx.obj = CmdState()
    ctx.obj.pprint = pprint
    ctx.obj.doc = bundle_doc
    ctx.obj.graph = build_split_graph(bundle_doc)


@cli_app.command()
def categories(ctx: typer.Context) -> None:
    "List the categories"

    the_categories: List[str] = [
        Emb3dCategory.HARDWARE,
        Emb3dCategory.SYSTEM_SW,
        Emb3dCategory.APP_SW,
        Emb3dCategory.NETWORKING,
    ]

    adapter = TypeAdapter(List[str])

    sys.stdout.write(adapter.dump_json(the_categories, indent=0).decode("utf-8"))


def _collect_properties_json(G: Any, props: list, current_level: int, max_level: int) -> list[dict[str, Any]]:
    result = []
    for prop in props:
        item: dict[str, Any] = {"id": prop.x_mitre_emb3d_property_id, "name": prop.name}
        if current_level < max_level:
            subs = get_subproperties(G, prop)
            if subs:
                item["subproperties"] = _collect_properties_json(G, subs, current_level + 1, max_level)
        result.append(item)
    return result


def _print_properties_pprint(G: Any, props: list, current_level: int, max_level: int, indent: int = 0) -> None:
    for prop in props:
        rprint(f"{'  ' * indent}- {prop.x_mitre_emb3d_property_id}: {prop.name}")
        if current_level < max_level:
            subs = get_subproperties(G, prop)
            if subs:
                _print_properties_pprint(G, subs, current_level + 1, max_level, indent + 1)


@cli_app.command()
def properties(
    ctx: typer.Context,
    category: Emb3dCategory,
    level: Annotated[
        int,
        typer.Option(help="Depth of sub-properties to include (1 = top-level only, 2 = include sub-properties, etc.)"),
    ] = 1,
) -> None:
    """Get list of properties for a certain category"""

    state = cast(CmdState, ctx.obj)
    G = state.graph

    device_properties = get_properties_by_category(G, category)

    if state.pprint:
        _print_properties_pprint(G, device_properties, 1, level)
    else:
        result = _collect_properties_json(G, device_properties, 1, level)
        sys.stdout.write(json.dumps(result, indent=None))


@cli_app.command()
def threats(ctx: typer.Context, category: Emb3dCategory) -> None:
    "List of threats for a certain category"

    state = cast(CmdState, ctx.obj)
    G = state.graph

    threats = get_threats_by_category(G, category)

    if state.pprint:
        for v in threats:
            rprint(f"- {v.x_mitre_emb3d_threat_id}: {v.name}")
    else:
        result = [{"id": v.x_mitre_emb3d_threat_id, "name": v.name} for v in threats]
        sys.stdout.write(json.dumps(result, indent=None))


@cli_app.command()
def mitigations(ctx: typer.Context, threat_id: str) -> None:
    "List of mitigations for a certain threat"

    state = cast(CmdState, ctx.obj)
    G = state.graph

    mitigations = get_mitigations(G, threat_id)

    if state.pprint:
        for m in mitigations:
            rprint(f"- {m.x_mitre_emb3d_mitigation_id}: {m.name}")
    else:
        result = [{"id": m.x_mitre_emb3d_mitigation_id, "name": m.name} for m in mitigations]
        sys.stdout.write(json.dumps(result, indent=None))


@cli_app.command()
def serialize_graph(
    ctx: typer.Context,
    output: Annotated[Path, typer.Argument(help="Output file path to save the serialized graph (e.g. graph.graphml)")],
) -> None:
    """Serialize the graph to a GraphML file."""

    state = cast(CmdState, ctx.obj)
    G = state.graph

    write_graphml(G, output)
