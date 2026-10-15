"""Evaluation orchestration over the existing ScopeSentry-R services."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any

from app.evaluation.baseline import StaticScopeBaseline
from app.evaluation.schemas import EvaluationCase, OperationalOutcome
from app.gateway.contracts import calculate_scope_fingerprint
from app.gateway.policy_engine import evaluate_capability_attempt
from app.orchestrator.demo_runner import _detect_unauthorized_paths
from app.planner.analysis_service import analyze_scope_grant
from app.planner.composition_engine import analyze_composition
from app.providers.mock.adapter import MockGoogleProviderAdapter
from app.providers.mock.catalog import get_catalog
from app.schemas.gateway import CapabilityContract


_FIXED_TIME = datetime(2026, 1, 1, tzinfo=timezone.utc)


def combined_scopes(case: EvaluationCase) -> list[str]:
    return sorted({scope for grant in case.grants for scope in grant.granted_scopes})


def _contract_for_case(case: EvaluationCase, selected_scopes: list[str]) -> CapabilityContract:
    catalog = get_catalog(case.provider)
    capabilities = sorted({capability for scope in selected_scopes for capability in catalog.get(scope, [])})
    return CapabilityContract(
        contract_id=f"evaluation-{case.case_id}",
        provider=case.provider,
        intended_actions=sorted(case.intended_actions),
        allowed_scopes=selected_scopes,
        allowed_capabilities=capabilities,
        scope_fingerprint=calculate_scope_fingerprint(selected_scopes),
        created_at=_FIXED_TIME,
        expires_at=_FIXED_TIME + timedelta(days=1),
        state="active",
        policy_version="1.0.0",
        source_analysis_id=f"evaluation-{case.case_id}",
        source_evidence_hash="0" * 64,
    )


def _unauthorized_paths(case: EvaluationCase, required_capabilities: list[str]) -> list[dict[str, Any]]:
    if not case.composition_links:
        return []
    # This is the same production path detector used by DemoRunner. The
    # evaluation supplies its declared grants and links; it does not duplicate
    # or substitute the composition security rule.
    return _detect_unauthorized_paths(
        SimpleNamespace(data_flow_links=case.composition_links),
        case.grants,
        MockGoogleProviderAdapter(),
        required_capabilities,
    )


def evaluate_scope_sentry(case: EvaluationCase) -> dict[str, Any]:
    """Run one case through production analysis, composition, and policy."""
    original_scopes = combined_scopes(case)
    analysis = analyze_scope_grant(
        provider=case.provider,
        granted_scopes=original_scopes,
        intended_actions=case.intended_actions,
    )
    composition = None
    if len(case.grants) > 1 or case.composition_links:
        composition = analyze_composition(
            case.provider,
            [grant.model_dump(mode="python") for grant in case.grants],
            case.intended_actions,
        )
    paths = _unauthorized_paths(case, analysis["required_capabilities"])
    plan = analysis["least_privilege_plan"]
    decisions: list[dict[str, Any]] = []
    contract_created = False
    executed_scopes: list[list[str]] = []

    if analysis["unknown_intents"]:
        outcome = OperationalOutcome.MANUAL_REVIEW
    elif paths:
        outcome = OperationalOutcome.SKIPPED_UNSAFE_COMPOSITION
    elif analysis["missing_capabilities"] or plan["status"] != "complete":
        outcome = OperationalOutcome.CONTRACT_NOT_CREATED
    else:
        contract = _contract_for_case(case, plan["selected_scopes"])
        contract_created = True
        for attempt in case.runtime_attempts:
            decision = evaluate_capability_attempt(
                contract,
                attempted_capability=attempt.attempted_capability,
                observed_scopes=attempt.observed_scopes,
                now=_FIXED_TIME + timedelta(minutes=1),
            )
            if decision.get("decision") not in {"allow", "block", "quarantine"}:
                raise RuntimeError(
                    f"Malformed gateway decision for case '{case.case_id}': "
                    f"{decision.get('decision')!r}"
                )
            decisions.append(decision)
            if decision["decision"] == "allow":
                executed_scopes.append(sorted(set(attempt.observed_scopes)))
            if decision["state_transition"] is not None:
                contract = contract.model_copy(update={"state": decision["state_transition"]})

        decision_names = [item["decision"] for item in decisions]
        if "quarantine" in decision_names:
            outcome = OperationalOutcome.QUARANTINED
        elif "block" in decision_names:
            outcome = OperationalOutcome.BLOCKED
        elif plan["scopes_to_remove"]:
            outcome = OperationalOutcome.REMEDIATED_THEN_PERMITTED
        else:
            outcome = OperationalOutcome.PERMITTED_SAFE

    removed = sorted(plan["scopes_to_remove"])
    unsafe_execution = any(set(scopes) & set(removed) for scopes in executed_scopes)
    if decisions and any(item["decision"] == "allow" for item in decisions):
        unsafe_execution = unsafe_execution or any(
            set(item.get("unexpected_scopes", [])) for item in decisions if item["decision"] == "allow"
        )

    if case.ground_truth.classification == "safe":
        contained = outcome == OperationalOutcome.PERMITTED_SAFE
        normalized = "permitted" if contained else "prevented"
    else:
        contained = (
            not unsafe_execution
            and outcome
            in {
                OperationalOutcome.REMEDIATED_THEN_PERMITTED,
                OperationalOutcome.BLOCKED,
                OperationalOutcome.QUARANTINED,
                OperationalOutcome.CONTRACT_NOT_CREATED,
                OperationalOutcome.SKIPPED_UNSAFE_COMPOSITION,
                OperationalOutcome.MANUAL_REVIEW,
            }
        )
        normalized = "prevented" if contained else "permitted"

    result = {
        "operational_outcome": outcome.value,
        "normalized_result": normalized,
        "unsafe_authority_contained": contained if case.ground_truth.classification == "unsafe" else None,
        "original_unsafe_authority_executed": unsafe_execution,
        "contract_created": contract_created,
        "original_granted_scopes": original_scopes,
        "required_scopes": analysis["required_scopes"],
        "matched_scopes": analysis["matched_scopes"],
        "excessive_scopes": analysis["excessive_scopes"],
        "missing_scopes": analysis["missing_scopes"],
        "synthesized_scopes": plan["selected_scopes"],
        "removed_scopes": removed,
        "required_capabilities": analysis["required_capabilities"],
        "available_capabilities": analysis["granted_capabilities"],
        "missing_capabilities": analysis["missing_capabilities"],
        "gateway_decisions": [
            {
                "decision": item["decision"],
                "reason_code": item["reason_code"],
                "attempted_capability": item["attempted_capability"],
                "unexpected_scopes": item["unexpected_scopes"],
                "missing_scopes": item["missing_scopes"],
            }
            for item in decisions
        ],
        "executed_scopes": executed_scopes,
        "unauthorized_paths": paths,
        "unauthorized_path_count": len(paths),
        "remediation": sorted({path["remediation"] for path in paths}),
        "composition": composition,
    }
    return result


def evaluate_case(case: EvaluationCase, baseline: StaticScopeBaseline | None = None) -> dict[str, Any]:
    baseline_engine = baseline or StaticScopeBaseline()
    scopes = combined_scopes(case)
    baseline_result = baseline_engine.evaluate(
        provider=case.provider,
        intended_actions=case.intended_actions,
        granted_scopes=scopes,
    )
    scope_result = evaluate_scope_sentry(case)
    expected_normalized = "permitted" if case.ground_truth.classification == "safe" else "prevented"
    expected_outcome = case.ground_truth.expected_outcome.value
    return {
        "case_id": case.case_id,
        "category": case.category.value,
        "description": case.description,
        "ground_truth": case.ground_truth.model_dump(mode="json"),
        "expected_normalized_result": expected_normalized,
        "baseline": baseline_result.__dict__,
        "scope_sentry": scope_result,
        "baseline_matches_ground_truth": baseline_result.normalized_result == expected_normalized,
        "scope_sentry_matches_ground_truth": (
            scope_result["normalized_result"] == expected_normalized
            and scope_result["operational_outcome"] == expected_outcome
            and scope_result["unauthorized_path_count"] == case.ground_truth.expected_unauthorized_path_count
        ),
    }
