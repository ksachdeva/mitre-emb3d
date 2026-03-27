from collections.abc import AsyncIterator
from typing import Any, TypedDict

from fastmcp import Context, FastMCP
from fastmcp.server.lifespan import lifespan
from fastmcp.tools.function_tool import tool as fast_mcp_tool

from mitre_emb3d._graph import MITREGraph
from mitre_emb3d._models import (
    Emb3dCategory,
    Emb3dPropertyInfo,
    MitigationId,
    MitigationInfo,
    MitigationWithThreats,
    PropertyId,
    ThreatId,
    ThreatInfo,
    ThreatWithMitigations,
)


class LifeSpanState(TypedDict):
    graph: MITREGraph


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
def get_properties_for_category(ctx: Context, category: Emb3dCategory, level: int) -> list[Emb3dPropertyInfo]:
    """Get a list of properties for a given category and level."""
    mitre_graph: MITREGraph = ctx.lifespan_context["graph"]
    device_properties = mitre_graph.get_properties_for_category(category)
    return mitre_graph.collect_sub_properties(device_properties, 1, level)


@fast_mcp_tool()
def get_properties_for_threat(ctx: Context, threat_id: ThreatId) -> list[Emb3dPropertyInfo]:
    """Get a list of properties for a given threat and level."""
    mitre_graph: MITREGraph = ctx.lifespan_context["graph"]
    return mitre_graph.get_properties_for_threat(threat_id)


@fast_mcp_tool()
def get_threats_for_category(ctx: Context, category: Emb3dCategory) -> list[ThreatInfo]:
    """Get a list of threats for a given category."""
    mitre_graph: MITREGraph = ctx.lifespan_context["graph"]
    return mitre_graph.get_threats_for_category(category)


@fast_mcp_tool()
def get_threats_for_property(ctx: Context, property_id: PropertyId) -> list[ThreatInfo]:
    """Get a list of threats for a given Property."""
    mitre_graph: MITREGraph = ctx.lifespan_context["graph"]
    return mitre_graph.get_threats_for_property(property_id)


@fast_mcp_tool()
def get_mitigations(ctx: Context, threat_id: ThreatId) -> list[MitigationInfo]:
    """Get a list of mitigations for a given threat ID."""
    mitre_graph: MITREGraph = ctx.lifespan_context["graph"]
    return mitre_graph.get_mitigations(threat_id)


@fast_mcp_tool()
def get_threat(ctx: Context, threat_id: ThreatId) -> ThreatWithMitigations:
    """Get a threat by its ID, along with its mitigations."""
    mitre_graph: MITREGraph = ctx.lifespan_context["graph"]
    threat = mitre_graph.get_threat_from_id(threat_id)
    mitigations = mitre_graph.get_mitigations(threat_id)
    return ThreatWithMitigations(**threat.model_dump(), mitigations=mitigations)


@fast_mcp_tool()
def get_mitigation(ctx: Context, mitigation_id: MitigationId) -> MitigationWithThreats:
    """Get a mitigation by its ID, along with the threats it mitigates."""
    mitre_graph: MITREGraph = ctx.lifespan_context["graph"]
    mitigation = mitre_graph.get_mitigation_from_id(mitigation_id)
    threat_infos = mitre_graph.get_threat_info_for_mitigation(mitigation_id)
    return MitigationWithThreats(**mitigation.model_dump(), threats=threat_infos)


def build_mcp_server(graph: MITREGraph) -> FastMCP:
    @lifespan
    async def app_lifespan(server: FastMCP[Any]) -> AsyncIterator[dict[str, Any]]:
        yield LifeSpanState(graph=graph)  # type: ignore

    mcp = FastMCP(
        "MITRE EMB3D MCP Server",
        lifespan=app_lifespan,
    )

    mcp.add_tool(get_categories)
    mcp.add_tool(get_properties_for_category)
    mcp.add_tool(get_properties_for_threat)
    mcp.add_tool(get_threats_for_category)
    mcp.add_tool(get_threats_for_property)
    mcp.add_tool(get_mitigations)
    mcp.add_tool(get_threat)
    mcp.add_tool(get_mitigation)

    return mcp
