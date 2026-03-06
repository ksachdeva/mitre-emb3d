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
from mitre_emb3d._doc_loaders import from_release
from mitre_emb3d._graph import (
    build_split_graph,
    get_mitigations,
    get_properties_by_category,
    get_subproperties,
    get_vulnerabilities_by_category,
    make_default_heatmap,
    write_graphml,
)
from mitre_emb3d._locations import cache_directory
from mitre_emb3d._models import Emb3dCategory, ObjectType, ThreatHeatMap, ThreatResolution, ThreatState
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
    pprint: Annotated[bool, typer.Option(help="Whether to pretty-print the output (e.g. JSON lists)")] = False,
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
        for v in device_properties:
            rprint(f"- {v.x_mitre_emb3d_property_id}: {v.name}")
    else:
        result = [{"id": v.x_mitre_emb3d_property_id, "name": v.name} for v in device_properties]
        sys.stdout.write(json.dumps(result, indent=None))


@cli_app.command()
def threats(ctx: typer.Context, category: Emb3dCategory) -> None:
    "List of threats for a certain category"

    state = cast(CmdState, ctx.obj)
    G = state.graph

    vulnerabilities = get_vulnerabilities_by_category(G, category)

    if state.pprint:
        for v in vulnerabilities:
            rprint(f"- {v.x_mitre_emb3d_threat_id}: {v.name}")
    else:
        result = [{"id": v.x_mitre_emb3d_threat_id, "name": v.name} for v in vulnerabilities]
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


@cli_app.command()
def update_heatmap(
    ctx: typer.Context,
    category: Annotated[Emb3dCategory, typer.Argument(help="Category to update heatmap for")],
    threat_id: Annotated[
        str,
        typer.Argument(help="Threat ID to update (e.g. TID-123)"),
    ],
    threat_resolution: Annotated[ThreatResolution, typer.Argument()],
    heatmap_file: Annotated[Path, typer.Argument(help="Path to the heatmap JSON file")] = Path(
        "mitr-emb3d-heatmap.json"
    ),
) -> None:
    """Update the heatmap JSON file with the latest threat states from the graph."""

    state = cast(CmdState, ctx.obj)
    G = state.graph

    # check if the file exists, if not create an empty heatmap
    if heatmap_file.exists():
        heatmap_data = ThreatHeatMap.model_validate_json(heatmap_file.read_text())
    else:
        heatmap_data = make_default_heatmap(G, name="No name", description="No description")

    # check for this category the threat_id exists in the graph
    vulnerabilities = get_vulnerabilities_by_category(G, category)
    if not any(v.x_mitre_emb3d_threat_id == threat_id for v in vulnerabilities):
        raise ValueError(f"Threat ID '{threat_id}' not found in category '{category}'")

    heatmap_data.update_threat_state(category, threat_id, threat_resolution)

    heatmap_file.write_text(heatmap_data.model_dump_json(indent=2))
