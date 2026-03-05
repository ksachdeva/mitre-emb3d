import logging
import sys
from pathlib import Path
from re import L
from typing import Annotated, List, cast

import typer
from pydantic import TypeAdapter
from rich import print as rprint
from typer import Typer

from mitre_emb3d import __version__
from mitre_emb3d._doc_loaders import from_release
from mitre_emb3d._graph import (
    build_split_graph,
    get_properties_by_category,
    get_subproperties,
    get_vulnerabilities_by_category,
    write_graphml,
)
from mitre_emb3d._locations import cache_directory
from mitre_emb3d._models import Emb3dCategory, ObjectType
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
    cache: Annotated[bool, typer.Option(help="Whether to cache the emb3d-stix.json file for future use")] = True,
) -> None:
    logging.basicConfig(level=LOG_LEVELS.get(loglevel, logging.WARNING))
    logging.getLogger("mitre_emb3d").setLevel(LOG_LEVELS.get(loglevel, logging.WARNING))

    # cache file_name
    file_name = cache_directory().joinpath(f"emb3d-stix-{release}.json")

    if file_name.exists() and cache:
        _LOGGER.info(f"Loading emb3d-stix-{release}.json from cache ...")
        bundle_doc = ST.model_validate_json(file_name.read_text())
    else:
        bundle_doc = from_release(release)
        file_name.write_text(bundle_doc.model_dump_json())

    ctx.ensure_object(CmdState)
    ctx.obj = CmdState()
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


@cli_app.command()
def get_properties(
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

    def _sort_key(node_id: str) -> int:
        pid = G.nodes[node_id].get("x_mitre_emb3d_property_id", "PID-0")
        return int(pid.split("-")[1])

    def print_tree(node_id: str, indent: int, current_depth: int) -> None:
        props = G.nodes[node_id]
        prefix = "  " * indent + "- "
        rprint(f"{prefix}{props.get('x_mitre_emb3d_property_id')}: {props.get('name')}")
        if current_depth < level:
            subs = sorted(get_subproperties(G, node_id), key=_sort_key)
            for sub in subs:
                print_tree(sub, indent + 1, current_depth + 1)

    top_level = sorted(get_properties_by_category(G, category), key=_sort_key)
    for node_id in top_level:
        print_tree(node_id, indent=0, current_depth=1)


@cli_app.command()
def get_threats(ctx: typer.Context, category: Emb3dCategory) -> None:
    "List of threats for a certain category"

    state = cast(CmdState, ctx.obj)
    G = state.graph

    vulnerabilities = get_vulnerabilities_by_category(G, category)
    vulns = sorted(
        (G.nodes[v] for v in vulnerabilities),
        key=lambda v: int(v.get("x_mitre_emb3d_threat_id", "TID-0").split("-")[1]),
    )
    for v in vulns:
        rprint(f"- {v.get('x_mitre_emb3d_threat_id')}: {v.get('name')}")


@cli_app.command()
def get_mitigations(ctx: typer.Context, threat_id: str) -> None:
    "List of mitigations for a certain threat"

    state = cast(CmdState, ctx.obj)
    G = state.graph

    mitigations = [
        G.nodes[source]
        for source, target, data in G.edges(data=True)
        if data.get("relationship_type") == "mitigates" and G.nodes[target].get("x_mitre_emb3d_threat_id") == threat_id
    ]

    mitigs = sorted(
        mitigations,
        key=lambda m: int(m.get("x_mitre_emb3d_mitigation_id", "MID-0").split("-")[1]),
    )
    for m in mitigs:
        rprint(f"- {m.get('x_mitre_emb3d_mitigation_id')}: {m.get('name')}")


@cli_app.command()
def serialize_graph(
    ctx: typer.Context,
    output: Annotated[Path, typer.Argument(help="Output file path to save the serialized graph (e.g. graph.graphml)")],
) -> None:
    """Serialize the graph to a GraphML file."""

    state = cast(CmdState, ctx.obj)
    G = state.graph

    write_graphml(G, output)
