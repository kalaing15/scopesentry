"""
Compositional OAuth capability graph engine.

Builds a directed graph using NetworkX with:
  - **Scope nodes**  – each granted or required scope
  - **Capability nodes** – concrete capabilities enabled by scopes
  - **ENABLES edges** – from scope → capability

Node and edge attributes indicate classification (granted / required /
excessive / missing for scopes; required / excessive for capabilities).

The graph is serialised to a JSON-friendly ``{"nodes": [...], "edges": [...]}``
structure.
"""

from typing import Any, Dict, List, Set, Tuple

import networkx as nx

from app.providers.mock.catalog import get_catalog


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------

def build_capability_graph(
    provider: str,
    granted_scopes: List[str],
    required_scopes: List[str],
) -> Tuple[nx.DiGraph, Dict[str, Any]]:
    """Build and classify a scope → capability directed graph.

    Returns
    -------
    graph : nx.DiGraph
        The populated NetworkX graph.
    analysis : dict
        ``granted_capabilities``, ``required_capabilities``,
        ``excessive_capabilities``, and ``missing_capabilities`` sets
        converted to sorted lists.
    """
    catalog = get_catalog(provider)

    granted_set: Set[str] = set(granted_scopes)
    required_set: Set[str] = set(required_scopes)

    graph = nx.DiGraph()

    # Track capabilities reachable from each category
    granted_caps: Set[str] = set()
    required_caps: Set[str] = set()

    # --- Add scope nodes & capability nodes ---------------------------------
    all_scopes = granted_set | required_set

    for scope in sorted(all_scopes):
        # Classify scope
        if scope in granted_set and scope in required_set:
            scope_status = "matched"
        elif scope in granted_set:
            scope_status = "excessive"
        else:
            scope_status = "missing"

        graph.add_node(
            scope,
            node_type="scope",
            status=scope_status,
        )

        # Capabilities enabled by this scope (skip unknown scopes)
        capabilities = catalog.get(scope, [])
        for cap in capabilities:
            # Add capability node (idempotent – no duplicates)
            if not graph.has_node(cap):
                graph.add_node(cap, node_type="capability", status="unknown")

            # Add edge
            graph.add_edge(scope, cap, relation="ENABLES")

            # Bookkeeping
            if scope in granted_set:
                granted_caps.add(cap)
            if scope in required_set:
                required_caps.add(cap)

    # --- Classify capability nodes ------------------------------------------
    excessive_caps = granted_caps - required_caps
    missing_caps = required_caps - granted_caps

    for cap in graph.nodes:
        if graph.nodes[cap].get("node_type") != "capability":
            continue
        if cap in required_caps and cap not in excessive_caps:
            graph.nodes[cap]["status"] = "required"
        elif cap in excessive_caps:
            graph.nodes[cap]["status"] = "excessive"
        else:
            graph.nodes[cap]["status"] = "required"

    analysis = {
        "granted_capabilities": sorted(granted_caps),
        "required_capabilities": sorted(required_caps),
        "excessive_capabilities": sorted(excessive_caps),
        "missing_capabilities": sorted(missing_caps),
    }

    return graph, analysis


# ---------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------

def graph_to_serializable(graph: nx.DiGraph) -> Dict[str, Any]:
    """Convert a NetworkX DiGraph to a JSON-serializable dict.

    Returns ``{"nodes": [...], "edges": [...]}``.
    """
    nodes = []
    for node_id, attrs in graph.nodes(data=True):
        nodes.append({"id": node_id, **attrs})

    edges = []
    for source, target, attrs in graph.edges(data=True):
        edges.append({"source": source, "target": target, **attrs})

    return {"nodes": nodes, "edges": edges}
