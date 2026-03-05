"""Build a NetworkX graph from Bundle"""

from pathlib import Path

import networkx as nx

from ._models import Emb3dCategory, ObjectType, StixBundle


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
    G.add_node(str(Emb3dCategory.HARDWARE), object_type="category")
    G.add_node(str(Emb3dCategory.SYSTEM_SW), object_type="category")
    G.add_node(str(Emb3dCategory.APP_SW), object_type="category")
    G.add_node(str(Emb3dCategory.NETWORKING), object_type="category")

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


def get_vulnerabilities_by_category(G: nx.DiGraph, category: str) -> list[str]:
    """Return a list of vulnerability node IDs for a given category.

    Edge directions in the graph:
      top-level-property ──► category
      sub-property       ──► parent-property
      property           ──► vulnerability  (relates-to)

    So vulnerabilities are *successors* of property nodes, not ancestors of
    the category.  The traversal is therefore:
      1. Collect all emb3d-property nodes that are ancestors of ``category``
         (i.e. top-level properties and sub-properties whose chain leads to it).
      2. Walk each property's successors and keep vulnerability nodes.

    Args:
        G: The directed graph built by :func:`build_split_graph`.
        category: The category node label, e.g. ``"Hardware"``.

    Returns:
        A deduplicated list of vulnerability node IDs.
    """
    if category not in G:
        raise ValueError(
            f"Category '{category}' not found in graph. "
            f"Valid categories: {[n for n, d in G.nodes(data=True) if d.get('object_type') == 'category']}"
        )

    property_nodes = {
        n for n in nx.ancestors(G, category) if G.nodes[n].get("object_type") == str(ObjectType.EMB3D_PROPERTY)
    }

    seen: set[str] = set()
    result: list[str] = []
    for prop in property_nodes:
        for successor in G.successors(prop):
            if successor not in seen and G.nodes[successor].get("object_type") == str(ObjectType.VULNERABILITY):
                seen.add(successor)
                result.append(successor)

    return result


def write_graphml(G: nx.DiGraph, output_path: Path) -> None:
    """Write the graph to a GraphML file."""
    nx.write_graphml(G, output_path)
