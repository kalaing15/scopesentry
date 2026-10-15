"""
Deterministic least-privilege scope synthesis engine.

Uses exhaustive subset evaluation over the provider's scope catalogue to
find the safest combination of scopes that covers every required capability.

**This module only generates a recommendation plan.  It never silently
modifies or revokes real OAuth permissions.**
"""

from itertools import combinations
from typing import Any, Dict, List, Optional, Set, Tuple

from app.providers.mock.catalog import (
    DEFAULT_RISK_WEIGHT,
    get_catalog,
    get_risk_weights,
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def synthesize_least_privilege(
    provider: str,
    granted_scopes: List[str],
    required_capabilities: List[str],
    unknown_intents: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Synthesize the optimal least-privilege scope set.

    Parameters
    ----------
    provider : str
        OAuth provider key (e.g. ``"google"``).
    granted_scopes : list[str]
        Scopes the application currently holds.
    required_capabilities : list[str]
        Capabilities that must be covered.
    unknown_intents : list[str] | None
        Any intentions the system could not map.  Triggers
        ``manual_review`` status when non-empty.

    Returns
    -------
    dict
        A ``LeastPrivilegePlan``-compatible dictionary.
    """
    # --- Short-circuit: unknown intents → manual review ---------------------
    if unknown_intents:
        return _manual_review_plan(
            granted_scopes=granted_scopes,
            required_capabilities=required_capabilities,
            unknown_intents=unknown_intents,
            provider=provider,
        )

    catalog = get_catalog(provider)
    weights = get_risk_weights(provider)
    granted_set = set(granted_scopes)
    required_caps = set(required_capabilities)

    # --- Pre-compute capability sets for every catalogue scope --------------
    scope_caps: Dict[str, Set[str]] = {
        scope: set(caps) for scope, caps in catalog.items()
    }

    # All capabilities achievable through the entire catalogue
    all_achievable: Set[str] = set()
    for caps in scope_caps.values():
        all_achievable |= caps

    uncovered_capabilities = sorted(required_caps - all_achievable)

    # If the catalogue cannot cover everything → incomplete
    if uncovered_capabilities:
        return _incomplete_plan(
            granted_scopes=granted_scopes,
            required_capabilities=required_capabilities,
            uncovered_capabilities=uncovered_capabilities,
            provider=provider,
        )

    # --- Exhaustive search over subsets of catalogue scopes -----------------
    candidate_scopes = sorted(catalog.keys())
    best: Optional[Tuple[List[str], Set[str]]] = None
    best_key: Optional[Tuple[float, int, int, List[str]]] = None

    # Include the empty subset: when no capabilities are required, selecting
    # no scopes is the unique minimum-risk least-privilege plan.
    for size in range(len(candidate_scopes) + 1):
        for combo in combinations(candidate_scopes, size):
            covered = set()
            for s in combo:
                covered |= scope_caps[s]

            if not required_caps.issubset(covered):
                continue

            total_risk = sum(
                weights.get(s, DEFAULT_RISK_WEIGHT) for s in combo
            )
            unnecessary_caps = covered - required_caps
            combo_sorted = sorted(combo)

            key = (
                total_risk,
                len(unnecessary_caps),
                len(combo_sorted),
                combo_sorted,
            )

            if best_key is None or key < best_key:
                best_key = key
                best = (combo_sorted, covered)

    assert best is not None  # guaranteed because uncovered check passed

    selected_scopes, covered_caps = best

    # --- Compute plan fields ------------------------------------------------
    selected_set = set(selected_scopes)

    scopes_to_keep = sorted(granted_set & selected_set)
    scopes_to_remove = sorted(granted_set - selected_set)
    scopes_to_add = sorted(selected_set - granted_set)

    covered_capabilities = sorted(required_caps & covered_caps)
    unnecessary_capabilities = sorted(covered_caps - required_caps)

    risk_before = round(
        sum(weights.get(s, DEFAULT_RISK_WEIGHT) for s in granted_set), 2
    )
    risk_after = round(
        sum(weights.get(s, DEFAULT_RISK_WEIGHT) for s in selected_set), 2
    )
    risk_delta = round(risk_before - risk_after, 2)
    risk_reduction_percentage = (
        round((risk_delta / risk_before) * 100, 2)
        if risk_before > 0
        else 0.0
    )

    explanation = _build_explanation(
        scopes_to_remove=scopes_to_remove,
        scopes_to_add=scopes_to_add,
        unnecessary_capabilities=unnecessary_capabilities,
        risk_reduction_percentage=risk_reduction_percentage,
        catalog=catalog,
    )

    return {
        "status": "complete",
        "selected_scopes": selected_scopes,
        "scopes_to_keep": scopes_to_keep,
        "scopes_to_remove": scopes_to_remove,
        "scopes_to_add": scopes_to_add,
        "covered_capabilities": covered_capabilities,
        "uncovered_capabilities": [],
        "unnecessary_capabilities": unnecessary_capabilities,
        "risk_before": risk_before,
        "risk_after": risk_after,
        "risk_delta": risk_delta,
        "risk_reduction_percentage": risk_reduction_percentage,
        "optimization_method": "exhaustive_subset_evaluation",
        "explanation": explanation,
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _manual_review_plan(
    *,
    granted_scopes: List[str],
    required_capabilities: List[str],
    unknown_intents: List[str],
    provider: str,
) -> Dict[str, Any]:
    """Return a plan with ``manual_review`` status."""
    weights = get_risk_weights(provider)
    granted_set = set(granted_scopes)
    risk_before = round(
        sum(weights.get(s, DEFAULT_RISK_WEIGHT) for s in granted_set), 2
    )
    return {
        "status": "manual_review",
        "selected_scopes": [],
        "scopes_to_keep": [],
        "scopes_to_remove": [],
        "scopes_to_add": [],
        "covered_capabilities": [],
        "uncovered_capabilities": sorted(required_capabilities),
        "unnecessary_capabilities": [],
        "risk_before": risk_before,
        "risk_after": 0.0,
        "risk_delta": 0.0,
        "risk_reduction_percentage": 0.0,
        "optimization_method": "exhaustive_subset_evaluation",
        "explanation": (
            "Automatic synthesis is not possible because the following "
            "intentions could not be mapped to known capabilities: "
            f"{unknown_intents}. Manual review is required."
        ),
    }


def _incomplete_plan(
    *,
    granted_scopes: List[str],
    required_capabilities: List[str],
    uncovered_capabilities: List[str],
    provider: str,
) -> Dict[str, Any]:
    """Return a plan with ``incomplete`` status."""
    weights = get_risk_weights(provider)
    granted_set = set(granted_scopes)
    risk_before = round(
        sum(weights.get(s, DEFAULT_RISK_WEIGHT) for s in granted_set), 2
    )
    return {
        "status": "incomplete",
        "selected_scopes": [],
        "scopes_to_keep": [],
        "scopes_to_remove": [],
        "scopes_to_add": [],
        "covered_capabilities": sorted(
            set(required_capabilities) - set(uncovered_capabilities)
        ),
        "uncovered_capabilities": uncovered_capabilities,
        "unnecessary_capabilities": [],
        "risk_before": risk_before,
        "risk_after": 0.0,
        "risk_delta": 0.0,
        "risk_reduction_percentage": 0.0,
        "optimization_method": "exhaustive_subset_evaluation",
        "explanation": (
            "The provider catalogue cannot cover all required capabilities. "
            f"Uncovered: {uncovered_capabilities}."
        ),
    }


def _build_explanation(
    *,
    scopes_to_remove: List[str],
    scopes_to_add: List[str],
    unnecessary_capabilities: List[str],
    risk_reduction_percentage: float,
    catalog: Dict[str, List[str]],
) -> str:
    """Build a human-readable explanation of the synthesis result."""
    parts: List[str] = []

    if scopes_to_remove:
        for scope in scopes_to_remove:
            caps = catalog.get(scope, [])
            cap_names = ", ".join(caps) if caps else "no recognized capabilities"
            parts.append(
                f"Scope '{scope}' should be removed because its capabilities "
                f"({cap_names}) are not required for the selected intent."
            )

    if scopes_to_add:
        for scope in scopes_to_add:
            caps = catalog.get(scope, [])
            cap_names = ", ".join(caps) if caps else "unknown capabilities"
            parts.append(
                f"Scope '{scope}' should be added to enable: {cap_names}."
            )

    if not scopes_to_remove and not scopes_to_add:
        parts.append(
            "The current scope set already matches the least-privilege "
            "recommendation. No changes are needed."
        )

    if risk_reduction_percentage > 0:
        parts.append(
            f"This change reduces the overall risk score by "
            f"{risk_reduction_percentage}%."
        )

    return " ".join(parts)
