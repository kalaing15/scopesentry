"""Deterministic analysis of authority distributed across multiple grants.

The engine is recommendation-only. It never changes, revokes, or provisions
OAuth grants. Unknown scopes are retained as evidence but never treated as
capability sources.
"""

from collections import defaultdict
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set

from app.planner.intent_mapper import map_intents_to_scopes
from app.planner.least_privilege_synthesizer import synthesize_least_privilege
from app.providers.mock.catalog import (
    DEFAULT_RISK_WEIGHT,
    get_catalog,
    get_risk_weights,
)


def _stable_unique(values: Iterable[str]) -> List[str]:
    """Return stripped, non-empty values in stable first-seen order."""
    result: List[str] = []
    seen: Set[str] = set()
    for value in values:
        normalized = value.strip()
        if normalized and normalized not in seen:
            seen.add(normalized)
            result.append(normalized)
    return result


def _grant_value(grant: Any, field: str, default: Any = None) -> Any:
    if isinstance(grant, Mapping):
        if field == "grant_id":
            return grant.get("grant_id", grant.get("id", grant.get("name")))
        if field == "granted_scopes":
            return grant.get("granted_scopes", grant.get("scopes", default))
        return grant.get(field, default)
    return getattr(grant, field, default)


def analyze_composition(
    provider: str,
    grants: Sequence[Any],
    intended_actions: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Analyze the union and provenance of capabilities across grants."""
    catalog = get_catalog(provider)
    weights = get_risk_weights(provider)
    provider_key = provider.strip().lower()

    normalized_grants: List[Dict[str, Any]] = []
    grant_ids: Set[str] = set()
    all_intents: List[str] = list(intended_actions or [])

    for grant in grants:
        raw_grant_id = _grant_value(grant, "grant_id")
        if raw_grant_id is None or not str(raw_grant_id).strip():
            raise ValueError("Every grant must have a non-blank grant_id")
        grant_id = str(raw_grant_id).strip()
        if grant_id in grant_ids:
            raise ValueError("grant_id values must be unique")
        grant_ids.add(grant_id)

        grant_intents = _stable_unique(
            _grant_value(grant, "intended_actions", []) or []
        )
        all_intents.extend(grant_intents)
        normalized_grants.append(
            {
                "grant_id": grant_id,
                "granted_scopes": sorted(
                    set(_grant_value(grant, "granted_scopes", []) or [])
                ),
                "intended_actions": grant_intents,
            }
        )

    all_intents = _stable_unique(all_intents)
    required_scopes, unknown_intents = map_intents_to_scopes(
        all_intents, provider_key
    )
    required_capabilities = sorted(
        {
            capability
            for scope in required_scopes
            for capability in catalog.get(scope, [])
        }
    )
    required_capability_set = set(required_capabilities)

    combined_scopes: Set[str] = set()
    combined_capabilities: Set[str] = set()
    scope_sources: Dict[str, Set[str]] = defaultdict(set)
    capability_sources: Dict[str, Set[str]] = defaultdict(set)
    per_grant_capabilities: Dict[str, Set[str]] = {}
    grant_analyses: List[Dict[str, Any]] = []
    total_risk = 0.0

    nodes: Dict[str, Dict[str, Any]] = {}
    edges: Set[tuple[str, str, str]] = set()

    for grant in sorted(normalized_grants, key=lambda item: item["grant_id"]):
        grant_id = grant["grant_id"]
        scopes = grant["granted_scopes"]
        recognized_scopes = sorted(scope for scope in scopes if scope in catalog)
        unknown_scopes = sorted(scope for scope in scopes if scope not in catalog)
        capabilities = {
            capability
            for scope in recognized_scopes
            for capability in catalog[scope]
        }
        per_grant_capabilities[grant_id] = capabilities
        combined_scopes.update(scopes)
        combined_capabilities.update(capabilities)

        risk_score = round(
            sum(weights.get(scope, DEFAULT_RISK_WEIGHT) for scope in scopes),
            2,
        )
        total_risk += risk_score

        grant_node_id = f"grant:{grant_id}"
        nodes[grant_node_id] = {
            "id": grant_node_id,
            "node_type": "grant",
            "grant_id": grant_id,
            "provider": provider_key,
        }

        for scope in scopes:
            scope_sources[scope].add(grant_id)
            scope_node_id = f"grant:{grant_id}:scope:{scope}"
            nodes[scope_node_id] = {
                "id": scope_node_id,
                "node_type": "scope",
                "scope": scope,
                "grant_id": grant_id,
                "provider": provider_key,
                "status": "recognized" if scope in catalog else "unknown",
            }
            edges.add((grant_node_id, scope_node_id, "HAS_SCOPE"))

            for capability in catalog.get(scope, []):
                capability_sources[capability].add(grant_id)
                capability_node_id = f"capability:{capability}"
                nodes[capability_node_id] = {
                    "id": capability_node_id,
                    "node_type": "capability",
                    "capability": capability,
                    "provider": provider_key,
                    "status": (
                        "required"
                        if capability in required_capability_set
                        else "excessive"
                    ),
                }
                edges.add(
                    (scope_node_id, capability_node_id, "ENABLES")
                )

        grant_analyses.append(
            {
                "grant_id": grant_id,
                "intended_actions": grant["intended_actions"],
                "granted_scopes": scopes,
                "recognized_scopes": recognized_scopes,
                "unknown_scopes": unknown_scopes,
                "capabilities": sorted(capabilities),
                "covers_all_required_capabilities": (
                    required_capability_set.issubset(capabilities)
                ),
                "risk_score": risk_score,
            }
        )

    matched_capabilities = sorted(
        combined_capabilities & required_capability_set
    )
    missing_capabilities = sorted(
        required_capability_set - combined_capabilities
    )
    excessive_capabilities = sorted(
        combined_capabilities - required_capability_set
    )
    duplicated_scopes = sorted(
        scope for scope, sources in scope_sources.items() if len(sources) > 1
    )
    shared_capabilities = sorted(
        capability
        for capability, sources in capability_sources.items()
        if len(sources) > 1
    )

    requires_composition = bool(required_capability_set) and (
        required_capability_set.issubset(combined_capabilities)
        and not any(
            required_capability_set.issubset(capabilities)
            for capabilities in per_grant_capabilities.values()
        )
    )

    combined_scope_list = sorted(combined_scopes)
    recognized_scope_list = sorted(combined_scopes & set(catalog))
    unknown_scope_list = sorted(combined_scopes - set(catalog))
    unique_scope_risk = round(
        sum(
            weights.get(scope, DEFAULT_RISK_WEIGHT)
            for scope in combined_scope_list
        ),
        2,
    )
    duplicated_scope_risk = round(total_risk - unique_scope_risk, 2)

    plan = synthesize_least_privilege(
        provider=provider_key,
        granted_scopes=combined_scope_list,
        required_capabilities=required_capabilities,
        unknown_intents=unknown_intents or None,
    )

    if unknown_intents:
        recommendation = (
            "Some intended actions are unknown, so the composed authority "
            "requires manual review."
        )
    elif plan["status"] == "incomplete":
        recommendation = (
            "The provider catalogue cannot cover every required capability."
        )
    elif missing_capabilities:
        recommendation = (
            "The current grants are missing required capabilities; apply the "
            "least-privilege additions from the recommendation plan."
        )
    elif unknown_scope_list:
        recommendation = (
            "Unknown scopes were excluded from capability claims and should "
            "be reviewed or removed."
        )
    elif excessive_capabilities or duplicated_scopes:
        recommendation = (
            "The composed grants contain excessive or duplicated authority; "
            "use the least-privilege plan to reduce exposure."
        )
    elif requires_composition:
        recommendation = (
            "The required capability set is satisfied only by composing "
            "multiple grants."
        )
    else:
        recommendation = (
            "The composed grants provide the required capabilities without "
            "detected excess authority."
        )

    graph = {
        "nodes": [nodes[node_id] for node_id in sorted(nodes)],
        "edges": [
            {"source": source, "target": target, "relation": relation}
            for source, target, relation in sorted(edges)
        ],
    }

    return {
        "status": plan["status"],
        "provider": provider_key,
        "grant_count": len(normalized_grants),
        "intended_actions": all_intents,
        "unknown_intents": sorted(set(unknown_intents)),
        "required_scopes": required_scopes,
        "required_capabilities": required_capabilities,
        "grants": grant_analyses,
        "combined_scopes": combined_scope_list,
        "recognized_scopes": recognized_scope_list,
        "unknown_scopes": unknown_scope_list,
        "combined_capabilities": sorted(combined_capabilities),
        "matched_capabilities": matched_capabilities,
        "missing_capabilities": missing_capabilities,
        "excessive_capabilities": excessive_capabilities,
        "duplicated_scopes": duplicated_scopes,
        "shared_capabilities": shared_capabilities,
        "capability_sources": {
            capability: sorted(sources)
            for capability, sources in sorted(capability_sources.items())
        },
        "requires_composition": requires_composition,
        "total_risk": round(total_risk, 2),
        "unique_scope_risk": unique_scope_risk,
        "duplicated_scope_risk": duplicated_scope_risk,
        "composition_graph": graph,
        "least_privilege_plan": plan,
        "recommendation": recommendation,
    }


def analyze_grant_composition(
    provider: str,
    grants: Sequence[Any],
    intended_actions: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Backward-compatible descriptive alias for ``analyze_composition``."""
    return analyze_composition(provider, grants, intended_actions)
