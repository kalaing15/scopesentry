"""Reusable single-grant analysis service shared by API and demos."""

from typing import Any, Dict, Iterable, List

from app.gateway.contracts import normalize_scopes
from app.planner.capability_graph import (
    build_capability_graph,
    graph_to_serializable,
)
from app.planner.exposure_engine import calculate_exposure_differential
from app.planner.intent_mapper import map_intents_to_scopes
from app.planner.least_privilege_synthesizer import synthesize_least_privilege
from app.providers.mock.catalog import resolve_authority_provider_id


class UnsupportedAnalysisProviderError(ValueError):
    pass


def analyze_scope_grant(
    *,
    provider: str,
    granted_scopes: Iterable[str],
    intended_actions: Iterable[str],
) -> Dict[str, Any]:
    """Run the complete deterministic analysis pipeline without HTTP."""
    try:
        provider_key = resolve_authority_provider_id(provider)
    except ValueError as exc:
        raise UnsupportedAnalysisProviderError(
            str(exc)
        ) from exc

    normalized_grants = normalize_scopes(granted_scopes)
    actions: List[str] = list(intended_actions)
    required_scopes, unknown_intents = map_intents_to_scopes(actions, provider_key)
    graph, capability_analysis = build_capability_graph(
        provider=provider_key,
        granted_scopes=normalized_grants,
        required_scopes=required_scopes,
    )
    differential = calculate_exposure_differential(
        granted_scopes=normalized_grants,
        required_scopes=required_scopes,
        provider=provider_key,
    )
    plan = synthesize_least_privilege(
        provider=provider_key,
        granted_scopes=normalized_grants,
        required_capabilities=capability_analysis["required_capabilities"],
        unknown_intents=unknown_intents or None,
    )

    if unknown_intents:
        recommendation = (
            "Some intentions are unsupported and require manual review."
        )
    elif plan["status"] == "incomplete":
        recommendation = (
            "The provider catalogue cannot fully cover the required "
            "capabilities. Manual review is needed."
        )
    elif differential["missing_scopes"]:
        recommendation = (
            "The granted scopes do not fully support the selected intent."
        )
    elif differential["excessive_scopes"]:
        recommendation = (
            "Remove the excessive scopes and use the synthesized "
            "least-privilege scope set."
        )
    else:
        recommendation = "The granted scopes match the selected intent."

    return {
        "provider": provider_key,
        "intended_actions": actions,
        "granted_scopes": normalized_grants,
        "required_scopes": required_scopes,
        "matched_scopes": differential["matched_scopes"],
        "excessive_scopes": differential["excessive_scopes"],
        "missing_scopes": differential["missing_scopes"],
        "unknown_intents": unknown_intents,
        "synthesized_least_privilege_scopes": plan["selected_scopes"],
        "granted_capabilities": capability_analysis["granted_capabilities"],
        "required_capabilities": capability_analysis["required_capabilities"],
        "missing_capabilities": capability_analysis["missing_capabilities"],
        "excessive_capabilities": capability_analysis[
            "excessive_capabilities"
        ],
        "exposure_score": differential["exposure_score"],
        "recommendation": recommendation,
        "capability_graph": graph_to_serializable(graph),
        "least_privilege_plan": plan,
    }
