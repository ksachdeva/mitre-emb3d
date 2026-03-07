"""Build a NetworkX graph from Bundle"""

from pathlib import Path

import networkx as nx

from ._models import (
    Emb3dCategory,
    Emb3dProperty,
    Mitigation,
    MitigationState,
    ObjectType,
    StixBundle,
    Threat,
    ThreatHeatMap,
    ThreatResolution,
    ThreatState,
)


def build_split_graph(bundle_doc: StixBundle) -> nx.DiGraph:
    G = nx.DiGraph()

    # the ids are too and mess with display
    vulnerability_node_counter = 0
    vulnerability_ids = {}
    course_of_action_node_counter = 0
    course_of_action_ids = {}
    emb3d_prop_node_counter = 0
    emb3d_ids = {}

    # create nodes for categories
    G.add_node(str(Emb3dCategory.HARDWARE), type="category")
    G.add_node(str(Emb3dCategory.SYSTEM_SW), type="category")
    G.add_node(str(Emb3dCategory.APP_SW), type="category")
    G.add_node(str(Emb3dCategory.NETWORKING), type="category")

    # first pass: add all nodes except relationships & edge to category nodes
    for item in bundle_doc.objects:
        if item.type == ObjectType.RELATIONSHIP or item.type == ObjectType.IDENTITY:
            continue  # skip relationships for now

        if item.type == ObjectType.VULNERABILITY:
            # assign a new id for the vulnerability node
            vulnerability_node_counter += 1
            new_id = f"vulnerability-{vulnerability_node_counter}"
            vulnerability_ids[item.id] = new_id

        if item.type == ObjectType.COURSE_OF_ACTION:
            # assign a new id for the course of action node
            course_of_action_node_counter += 1
            new_id = f"coa-{course_of_action_node_counter}"
            course_of_action_ids[item.id] = new_id

        if item.type == ObjectType.EMB3D_PROPERTY:
            # assign a new id for the emb3d property node
            emb3d_prop_node_counter += 1
            new_id = f"emb3d-property-{emb3d_prop_node_counter}"
            emb3d_ids[item.id] = new_id

        assert new_id is not None, "new_id should be set for non-relationship nodes"

        G.add_node(new_id, **item.graph_props())

        # create edge to appropriate category node
        if item.type == ObjectType.EMB3D_PROPERTY:
            if item.is_subproperty is False:
                G.add_edge(new_id, item.category)

    # second pass: add relationships as edges
    for item in bundle_doc.objects:
        if item.type != ObjectType.RELATIONSHIP:
            continue

        if item.source_ref in vulnerability_ids:
            source_ref = vulnerability_ids[item.source_ref]

        if item.source_ref in course_of_action_ids:
            source_ref = course_of_action_ids[item.source_ref]

        if item.source_ref in emb3d_ids:
            source_ref = emb3d_ids[item.source_ref]

        if item.target_ref in vulnerability_ids:
            target_ref = vulnerability_ids[item.target_ref]

        if item.target_ref in course_of_action_ids:
            target_ref = course_of_action_ids[item.target_ref]

        if item.target_ref in emb3d_ids:
            target_ref = emb3d_ids[item.target_ref]

        assert source_ref is not None
        assert target_ref is not None

        G.add_edge(
            source_ref,
            target_ref,
            **item.graph_props(),
        )

    return G


def get_mitigations(
    G: nx.DiGraph,
    threat_id: str,
) -> list[Mitigation]:
    mitigations = [
        Mitigation(**G.nodes[source])
        for source, target, data in G.edges(data=True)
        if data.get("relationship_type") == "mitigates" and G.nodes[target].get("threat_id") == threat_id
    ]

    mits = sorted(
        mitigations,
        key=lambda v: int(v.mitigation_id.split("-")[1]),
    )

    return mits


def get_threats_by_category(G: nx.DiGraph, category: Emb3dCategory) -> list[Threat]:
    if category not in G:
        raise ValueError(
            f"Category '{category}' not found in graph. "
            f"Valid categories: {[n for n, d in G.nodes(data=True) if d.get('type') == 'category']}"
        )

    property_nodes = {n for n in nx.ancestors(G, category) if G.nodes[n].get("type") == str(ObjectType.EMB3D_PROPERTY)}

    seen: set[str] = set()
    result: list[Threat] = []
    for prop in property_nodes:
        for successor in G.successors(prop):
            if successor not in seen and G.nodes[successor].get("type") == str(ObjectType.VULNERABILITY):
                seen.add(successor)
                result.append(Threat(**G.nodes[successor]))

    vulns = sorted(
        result,
        key=lambda v: int(v.threat_id.split("-")[1]),
    )

    return vulns


def get_threat_from_id(G: nx.DiGraph, threat_id: str) -> Threat:
    for _, d in G.nodes(data=True):
        if d.get("type") == str(ObjectType.VULNERABILITY) and d.get("threat_id") == threat_id:
            return Threat(**d)

    raise ValueError(f"Threat with id '{threat_id}' not found in graph.")


def get_mitigation_from_id(G: nx.DiGraph, mitigation_id: str) -> Mitigation:
    for _, d in G.nodes(data=True):
        if d.get("type") == str(ObjectType.COURSE_OF_ACTION) and d.get("mitigation_id") == mitigation_id:
            return Mitigation(**d)

    raise ValueError(f"Mitigation with id '{mitigation_id}' not found in graph.")


def get_threat_ids_for_mitigation(G: nx.DiGraph, mitigation_id: str) -> list[str]:
    return [
        G.nodes[target]["threat_id"]
        for source, target, data in G.edges(data=True)
        if data.get("relationship_type") == "mitigates" and G.nodes[source].get("mitigation_id") == mitigation_id
    ]


def get_properties_by_category(G: nx.DiGraph, category: Emb3dCategory) -> list[Emb3dProperty]:
    """Return top-level property node IDs that point to the given category."""
    if category not in G:
        raise ValueError(
            f"Category '{category}' not found in graph. "
            f"Valid categories: {[n for n, d in G.nodes(data=True) if d.get('type') == 'category']}"
        )
    return [
        Emb3dProperty(**G.nodes[n])
        for n in G.predecessors(category)
        if G.nodes[n].get("type") == str(ObjectType.EMB3D_PROPERTY)
    ]


def get_subproperties(G: nx.DiGraph, property_node: Emb3dProperty) -> list[Emb3dProperty]:
    """Return sub-property node IDs that point to the given property node."""
    # Graph nodes use remapped keys (e.g. "emb3d-property-1"), not the original STIX IDs
    graph_node_key = next(
        (n for n, d in G.nodes(data=True) if d.get("id") == property_node.id),
        None,
    )
    if graph_node_key is None:
        return []
    return [
        Emb3dProperty(**G.nodes[n])
        for n in G.predecessors(graph_node_key)
        if G.nodes[n].get("type") == str(ObjectType.EMB3D_PROPERTY)
    ]


def write_graphml(G: nx.DiGraph, output_path: Path) -> None:
    """Write the graph to a GraphML file."""
    nx.write_graphml(G, output_path)


def make_default_heatmap(G: nx.DiGraph, name: str, description: str) -> ThreatHeatMap:
    heatmap = ThreatHeatMap(
        name=name,
        description=description,
    )

    def _make_threat_state(threat: Threat) -> ThreatState:
        mitigations = get_mitigations(G, threat_id=threat.threat_id)
        mitigations_states = [MitigationState(mitigation_id=mit.mitigation_id) for mit in mitigations]
        return ThreatState(
            threat_id=threat.threat_id,
            resolution=ThreatResolution.NOT_INVESTIGATED,
            mitigations=mitigations_states,
        )

    heatmap.hardware = [_make_threat_state(v) for v in get_threats_by_category(G, Emb3dCategory.HARDWARE)]
    heatmap.system_software = [_make_threat_state(v) for v in get_threats_by_category(G, Emb3dCategory.SYSTEM_SW)]
    heatmap.application_software = [_make_threat_state(v) for v in get_threats_by_category(G, Emb3dCategory.APP_SW)]
    heatmap.networking = [_make_threat_state(v) for v in get_threats_by_category(G, Emb3dCategory.NETWORKING)]

    return heatmap
