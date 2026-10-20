"""Fair provider-aware conventional static OAuth scope baseline."""

from dataclasses import dataclass
from typing import Any, Iterable

from app.gateway.contracts import normalize_scopes
from app.planner.intent_mapper import map_intents_to_scopes
from app.providers.mock.catalog import get_catalog


@dataclass(frozen=True)
class BaselineResult:
    operational_outcome: str
    normalized_result: str
    required_scopes: list[str]
    granted_scopes: list[str]
    covered_required_scopes: list[str]
    missing_required_scopes: list[str]
    unknown_intents: list[str]
    explanation: str
    runtime_drift_detected: bool = False
    unauthorized_path_count: int = 0
    excessive_scopes_detected: tuple[str, ...] = ()


class StaticScopeBaseline:
    """Provider-aware static inclusion check without runtime safeguards.

    All grants are assumed to belong to the same explicitly declared local
    principal and provider. A known granted scope covers a required scope when
    it is identical or its catalogue capabilities are a superset. Extra scopes,
    runtime state, attempted capabilities, and data-flow links are ignored.
    """

    @staticmethod
    def scope_covers(provider: str, granted_scope: str, required_scope: str) -> bool:
        catalog = get_catalog(provider)
        if granted_scope not in catalog or required_scope not in catalog:
            return False
        return granted_scope == required_scope or set(catalog[required_scope]).issubset(catalog[granted_scope])

    def evaluate(
        self,
        *,
        provider: str,
        intended_actions: list[str],
        granted_scopes: Iterable[str],
    ) -> BaselineResult:
        required, unknown = map_intents_to_scopes(intended_actions, provider)
        granted = normalize_scopes(granted_scopes)
        if unknown:
            return BaselineResult(
                operational_outcome="manual_review",
                normalized_result="prevented",
                required_scopes=required,
                granted_scopes=granted,
                covered_required_scopes=[],
                missing_required_scopes=required,
                unknown_intents=sorted(unknown),
                explanation="Unmapped intent requires manual review; automatic execution is not permitted.",
            )
        covered = sorted(
            required_scope
            for required_scope in required
            if any(self.scope_covers(provider, scope, required_scope) for scope in granted)
        )
        missing = sorted(set(required) - set(covered))
        return BaselineResult(
            operational_outcome="blocked_missing_scope" if missing else "permitted",
            normalized_result="prevented" if missing else "permitted",
            required_scopes=required,
            granted_scopes=granted,
            covered_required_scopes=covered,
            missing_required_scopes=missing,
            unknown_intents=[],
            explanation=(
                f"Static scope coverage is missing: {missing}."
                if missing
                else "Every required scope is covered by an equal or catalogue-defined broader granted scope."
            ),
        )

    def evaluate_qualified(
        self,
        *,
        provider_intents: Iterable[Any],
        grants: Iterable[Any],
    ) -> BaselineResult:
        """Evaluate scope coverage within exact provider/principal boundaries."""
        grant_list = list(grants)
        all_required: list[str] = []
        all_granted = sorted(
            f"{grant.provider}:{grant.principal_id}:{scope}"
            for grant in grant_list
            for scope in grant.granted_scopes
        )
        covered: list[str] = []
        missing: list[str] = []
        unknown: list[str] = []
        for assignment in provider_intents:
            required, unmapped = map_intents_to_scopes(
                list(assignment.intended_actions), assignment.provider
            )
            unknown.extend(unmapped)
            principal = assignment.principal_id
            matching_scopes = sorted({
                scope
                for grant in grant_list
                if grant.provider == assignment.provider
                and (principal is None or grant.principal_id == principal)
                for scope in grant.granted_scopes
            })
            for required_scope in required:
                qualified = f"{assignment.provider}:{principal or '*'}:{required_scope}"
                all_required.append(qualified)
                if any(
                    self.scope_covers(
                        assignment.provider, granted_scope, required_scope
                    )
                    for granted_scope in matching_scopes
                ):
                    covered.append(qualified)
                else:
                    missing.append(qualified)
        if unknown:
            return BaselineResult(
                operational_outcome="manual_review",
                normalized_result="prevented",
                required_scopes=sorted(all_required),
                granted_scopes=all_granted,
                covered_required_scopes=sorted(covered),
                missing_required_scopes=sorted(set(missing) | set(all_required) - set(covered)),
                unknown_intents=sorted(unknown),
                explanation="Unsupported provider-specific intent requires manual review.",
            )
        return BaselineResult(
            operational_outcome="blocked_missing_scope" if missing else "permitted",
            normalized_result="prevented" if missing else "permitted",
            required_scopes=sorted(all_required),
            granted_scopes=all_granted,
            covered_required_scopes=sorted(covered),
            missing_required_scopes=sorted(missing),
            unknown_intents=[],
            explanation=(
                "Provider-qualified static coverage is incomplete."
                if missing
                else "Every provider-qualified static requirement is covered within the same principal boundary."
            ),
        )
