from collections.abc import AsyncIterator
from typing import Annotated, Any, cast

import networkx as nx
from fastmcp import Context, FastMCP
from fastmcp.server.lifespan import lifespan
from fastmcp.tools.function_tool import tool as fast_mcp_tool
from pydantic import Field

from mitre_emb3d._graph import (
    collect_sub_properties,
    get_mitigation_from_id,
    get_properties_for_category,
    get_threat_from_id,
    get_threat_info_for_mitigation,
)
from mitre_emb3d._graph import get_mitigations as get_mitigations_from_graph
from mitre_emb3d._graph import get_threats_for_category as get_threats_for_category_from_graph
from mitre_emb3d._graph import get_threats_for_property as get_threats_for_property_from_graph
from mitre_emb3d._models import (
    Emb3dCategory,
    Emb3dPropertyInfo,
    MitigationInfo,
    MitigationWithThreats,
    ThreatInfo,
    ThreatWithMitigations,
)
from mitre_emb3d.heatmap import HeatMapUpdateInfo, ThreatState
from mitre_emb3d.heatmap._protocols import HeatMapStorage, ProjectName


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
    device_properties = get_properties_for_category(G, category)
    return collect_sub_properties(G, device_properties, 1, level)


@fast_mcp_tool()
def get_threats_for_category(ctx: Context, category: Emb3dCategory) -> list[ThreatInfo]:
    """Get a list of threats for a given category."""
    G = ctx.lifespan_context["graph"]
    return get_threats_for_category_from_graph(G, category)


@fast_mcp_tool()
def get_threats_for_property(ctx: Context, property_id: str) -> list[ThreatInfo]:
    """Get a list of threats for a given Property."""
    G = ctx.lifespan_context["graph"]
    return get_threats_for_property_from_graph(G, property_id)


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
async def heatmap_init(
    ctx: Context,
    name: ProjectName,
    description: Annotated[str, Field(description="Description of the project")],
) -> None:
    """Initialize the heatmap for a project."""
    heatmap_storage = cast(HeatMapStorage, ctx.lifespan_context["heatmap_storage"])
    await heatmap_storage.initialize(name, description)


@fast_mcp_tool()
async def heatmap_read_entries(
    ctx: Context,
    name: ProjectName,
    category: Annotated[Emb3dCategory, Field(description="Category to list threat states for")],
) -> list[ThreatState]:
    """Read a heatmap entry for a specific threat."""
    heatmap_storage = cast(HeatMapStorage, ctx.lifespan_context["heatmap_storage"])
    return await heatmap_storage.read_entries(name, category)


@fast_mcp_tool()
async def heatmap_read_entry(
    ctx: Context,
    name: ProjectName,
    category: Annotated[Emb3dCategory, Field(description="Category to list threat states for")],
    threat_id: Annotated[str, Field(description="ID of the threat to get the state for")],
) -> ThreatState:
    """Read a heatmap entry for a specific threat."""
    heatmap_storage = cast(HeatMapStorage, ctx.lifespan_context["heatmap_storage"])
    return await heatmap_storage.read_entry(name, category, threat_id)


@fast_mcp_tool()
async def heatmap_update_entry(
    ctx: Context,
    name: ProjectName,
    category: Annotated[Emb3dCategory, Field(description="Category to which the threat belongs to")],
    threat_id: Annotated[
        str,
        Field(description="Threat ID to update (e.g. TID-123)"),
    ],
    update_info: Annotated[HeatMapUpdateInfo, Field(description="Information to update the heatmap entry with")],
) -> None:
    """Update a heatmap entry"""
    heatmap_storage = cast(HeatMapStorage, ctx.lifespan_context["heatmap_storage"])
    await heatmap_storage.update_entry(name, category, threat_id, update_info)


def build_mcp_server(graph: nx.DiGraph, heatmap_storage: HeatMapStorage) -> FastMCP:
    @lifespan
    async def app_lifespan(server: FastMCP[Any]) -> AsyncIterator[dict[str, Any]]:
        yield {"graph": graph, "heatmap_storage": heatmap_storage}

    mcp = FastMCP(
        "MITRE EMB3D MCP Server",
        lifespan=app_lifespan,
    )

    mcp.add_tool(get_categories)
    mcp.add_tool(get_properties)
    mcp.add_tool(get_threats_for_category)
    mcp.add_tool(get_threats_for_property)
    mcp.add_tool(get_mitigations)
    mcp.add_tool(get_threat)
    mcp.add_tool(get_mitigation)
    mcp.add_tool(heatmap_init)
    mcp.add_tool(heatmap_read_entries)
    mcp.add_tool(heatmap_read_entry)
    mcp.add_tool(heatmap_update_entry)

    return mcp
