from collections.abc import AsyncIterator
from pathlib import Path
from typing import Annotated, Any, Optional

import networkx as nx
from fastmcp import Context, FastMCP
from fastmcp.server.lifespan import lifespan
from fastmcp.tools.function_tool import tool as fast_mcp_tool
from pydantic import Field

from mitre_emb3d._graph import (
    collect_sub_properties,
    get_mitigation_from_id,
    get_properties_by_category,
    get_threat_from_id,
    get_threat_info_for_mitigation,
    get_threats_by_category,
    make_default_heatmap,
)
from mitre_emb3d._graph import get_mitigations as get_mitigations_from_graph
from mitre_emb3d._models import (
    Emb3dCategory,
    Emb3dPropertyInfo,
    MitigationInfo,
    MitigationWithThreats,
    ThreatHeatMap,
    ThreatInfo,
    ThreatResolution,
    ThreatState,
    ThreatWithMitigations,
)

ProjectName = Annotated[
    str,
    Field(
        description="Name of the project",
        min_length=1,
        pattern=r"^\S+$",
    ),
]


def _raise_if_threat_not_found(G: nx.DiGraph, category: Emb3dCategory, threat_id: str) -> None:
    # check for this category the threat_id exists in the graph
    threats = get_threats_by_category(G, category)
    if not any(v.id == threat_id for v in threats):
        raise ValueError(f"Threat ID '{threat_id}' not found in category '{category}'")


def _heatmap_file(output_dir: Path, name: str) -> Path:
    return output_dir / f"{name}-heatmap.json"


def _get_or_raise_heatmap_file(output_dir: Path, name: str) -> Path:
    heatmap_file = _heatmap_file(output_dir, name)
    if not heatmap_file.exists():
        raise ValueError(f"Heatmap file {heatmap_file} does not exist for project {name}")
    return heatmap_file


@fast_mcp_tool()
def get_categories() -> list[Emb3dCategory]:
    """Get a list of all categories"""
    the_categories: list[Emb3dCategory] = [
        Emb3dCategory.HARDWARE,
        Emb3dCategory.SYSTEM_SW,
        Emb3dCategory.APP_SW,
        Emb3dCategory.NETWORKING,
    ]
    return the_categories


@fast_mcp_tool()
def get_properties(ctx: Context, category: Emb3dCategory, level: int) -> list[Emb3dPropertyInfo]:
    """Get a list of properties for a given category and level."""
    G = ctx.lifespan_context["graph"]
    device_properties = get_properties_by_category(G, category)
    return collect_sub_properties(G, device_properties, 1, level)


@fast_mcp_tool()
def get_threats(ctx: Context, category: Emb3dCategory) -> list[ThreatInfo]:
    """Get a list of threats for a given category."""
    G = ctx.lifespan_context["graph"]
    return get_threats_by_category(G, category)


@fast_mcp_tool()
def get_mitigations(ctx: Context, threat_id: str) -> list[MitigationInfo]:
    """Get a list of mitigations for a given threat ID."""
    G = ctx.lifespan_context["graph"]
    return get_mitigations_from_graph(G, threat_id=threat_id)


@fast_mcp_tool()
def get_threat(ctx: Context, threat_id: str) -> ThreatWithMitigations:
    """Get a threat by its ID, along with its mitigations."""
    G = ctx.lifespan_context["graph"]
    threat = get_threat_from_id(G, threat_id)
    mitigations = get_mitigations_from_graph(G, threat_id=threat_id)
    return ThreatWithMitigations(**threat.model_dump(), mitigations=mitigations)


@fast_mcp_tool()
def get_mitigation(ctx: Context, mitigation_id: str) -> MitigationWithThreats:
    """Get a mitigation by its ID, along with the threats it mitigates."""
    G = ctx.lifespan_context["graph"]
    mitigation = get_mitigation_from_id(G, mitigation_id)
    threat_infos = get_threat_info_for_mitigation(G, mitigation_id)
    return MitigationWithThreats(**mitigation.model_dump(), threats=threat_infos)


@fast_mcp_tool()
def heatmap_init(
    ctx: Context,
    name: ProjectName,
    description: Annotated[str, Field(description="Description of the project")],
) -> None:
    """Initialize the heatmap for a project."""

    G = ctx.lifespan_context["graph"]
    output_dir = ctx.lifespan_context["output_dir"]

    heatmap_file = _heatmap_file(output_dir, name)

    if heatmap_file.exists():
        raise ValueError(f"Heatmap file {heatmap_file} already exists for project {name}")

    heatmap = make_default_heatmap(
        G,
        name=name,
        description=description,
    )

    heatmap_file.write_text(heatmap.model_dump_json(indent=2))


@fast_mcp_tool()
def heatmap_read_entries(
    ctx: Context,
    name: ProjectName,
    category: Annotated[Emb3dCategory, Field(description="Category to list threat states for")],
) -> list[ThreatState]:
    """Read a heatmap entry for a specific threat."""

    output_dir = ctx.lifespan_context["output_dir"]

    heatmap_file = _get_or_raise_heatmap_file(output_dir, name)
    heatmap_data = ThreatHeatMap.model_validate_json(heatmap_file.read_text())

    category_map = {
        Emb3dCategory.NETWORKING: heatmap_data.networking,
        Emb3dCategory.SYSTEM_SW: heatmap_data.system_software,
        Emb3dCategory.APP_SW: heatmap_data.application_software,
        Emb3dCategory.HARDWARE: heatmap_data.hardware,
    }

    return category_map.get(category, [])


@fast_mcp_tool()
def heatmap_read_entry(
    ctx: Context,
    name: ProjectName,
    category: Annotated[Emb3dCategory, Field(description="Category to list threat states for")],
    threat_id: Annotated[str, Field(description="ID of the threat to get the state for")],
) -> ThreatState:
    """Read a heatmap entry for a specific threat."""

    G = ctx.lifespan_context["graph"]
    _raise_if_threat_not_found(G, category, threat_id)

    output_dir = ctx.lifespan_context["output_dir"]
    heatmap_file = _get_or_raise_heatmap_file(output_dir, name)
    heatmap_data = ThreatHeatMap.model_validate_json(heatmap_file.read_text())

    category_map = {
        Emb3dCategory.NETWORKING: heatmap_data.networking,
        Emb3dCategory.SYSTEM_SW: heatmap_data.system_software,
        Emb3dCategory.APP_SW: heatmap_data.application_software,
        Emb3dCategory.HARDWARE: heatmap_data.hardware,
    }

    threats = category_map.get(category, [])

    for t in threats:
        if t.threat_id == threat_id:
            return t

    raise ValueError(f"Threat ID {threat_id} not found in category {category} for project {name}")


@fast_mcp_tool()
def heatmap_update_entry(
    ctx: Context,
    name: ProjectName,
    category: Annotated[Emb3dCategory, Field(description="Category to which the threat belongs to")],
    threat_id: Annotated[
        str,
        Field(description="Threat ID to update (e.g. TID-123)"),
    ],
    threat_resolution: Annotated[ThreatResolution, Field(description="New resolution for the threat")],
    applied_mitigations: Annotated[
        Optional[list[str]],
        Field(
            description="List of applied mitigation IDs (e.g. MID-001)",
        ),
    ] = None,
    unapplied_mitigations: Annotated[
        Optional[list[str]], Field(description="List of unapplied mitigation IDs (e.g. MID-002)")
    ] = None,
    notes: Annotated[Optional[str], Field(description="Additional notes about the threat state")] = None,
) -> None:
    """Update a heatmap entry"""

    G = ctx.lifespan_context["graph"]

    _raise_if_threat_not_found(G, category, threat_id)

    output_dir = ctx.lifespan_context["output_dir"]
    heatmap_file = _get_or_raise_heatmap_file(output_dir, name)
    heatmap_data = ThreatHeatMap.model_validate_json(heatmap_file.read_text())

    heatmap_data.update_threat_state(
        category,
        threat_id,
        threat_resolution,
        applied_mitigations=applied_mitigations,
        unapplied_mitigations=unapplied_mitigations,
        notes=notes,
    )

    heatmap_file.write_text(heatmap_data.model_dump_json(indent=2))


def build_mcp_server(graph: nx.DiGraph, output_dir: Path) -> FastMCP:
    @lifespan
    async def app_lifespan(server: FastMCP[Any]) -> AsyncIterator[dict[str, Any]]:
        yield {"graph": graph, "output_dir": output_dir}

    mcp = FastMCP(
        "MITRE EMB3D MCP Server",
        lifespan=app_lifespan,
    )

    mcp.add_tool(get_categories)
    mcp.add_tool(get_properties)
    mcp.add_tool(get_threats)
    mcp.add_tool(get_mitigations)
    mcp.add_tool(get_threat)
    mcp.add_tool(get_mitigation)
    mcp.add_tool(heatmap_init)
    mcp.add_tool(heatmap_read_entries)
    mcp.add_tool(heatmap_read_entry)
    mcp.add_tool(heatmap_update_entry)

    return mcp
