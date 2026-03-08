from collections.abc import AsyncIterator
from typing import Any

import networkx as nx
from fastmcp import Context, FastMCP
from fastmcp.server.lifespan import lifespan
from fastmcp.tools.function_tool import tool as fast_mcp_tool

from mitre_emb3d._graph import (
    collect_sub_properties,
    get_mitigation_from_id,
    get_properties_by_category,
    get_threat_from_id,
    get_threat_info_for_mitigation,
    get_threats_by_category,
)
from mitre_emb3d._graph import get_mitigations as get_mitigations_from_graph
from mitre_emb3d._models import (
    Emb3dCategory,
    Emb3dPropertyInfo,
    MitigationInfo,
    MitigationWithThreats,
    ThreatInfo,
    ThreatWithMitigations,
)


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


def build_mcp_server(graph: nx.DiGraph) -> FastMCP:
    @lifespan
    async def app_lifespan(server: FastMCP[Any]) -> AsyncIterator[dict[str, Any]]:
        yield {"graph": graph}

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

    return mcp
