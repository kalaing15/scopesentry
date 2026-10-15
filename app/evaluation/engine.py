"""Evaluation orchestration over the existing ScopeSentry-R services."""

from datetime import datetime, timedelta, timezone
from typing import Any

from app.evaluation.baseline import StaticScopeBaseline
from app.evaluation.schemas import EvaluationCase, OperationalOutcome
from app.gateway.contracts import calculate_scope_fingerprint
from app.gateway.policy_engine import evaluate_capability_attempt
from app.planner.analysis_service import analyze_scope_grant
from app.planner.composition_engine import analyze_composition
from app.providers.mock.catalog import get_catalog
from app.schemas.gateway import CapabilityContract
from app.schemas.provider import MockGrant, ProviderIntentAssignment, ScenarioDataFlowLink


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
    from app.planner.cross_provider_composition import analyze_provider_qualified_composition

    catalog = get_catalog(case.provider)
    grants = [
        MockGrant(
            grant_id=grant.grant_id,
            application_name=f"Evaluation {grant.grant_id}",
            provider=case.provider,
            authority_provider=case.provider,
            principal_id=case.principal_id,
            declared_intended_actions=[],
            granted_scopes=grant.granted_scopes,
            observed_scopes=grant.granted_scopes,
            status="active",
            description="Frozen Phase 4 evaluation grant.",
        )
        for grant in case.grants
    ]
    by_id = {grant.grant_id: grant for grant in grants}

    def capabilities(grant_id: str) -> list[str]:
        return sorted({cap for scope in by_id[grant_id].granted_scopes for cap in catalog.get(scope, ())})

    def semantic_choice(values: list[str], data_type: str, *, target: bool) -> str:
        data_tokens = set(data_type.split("_"))
        effect_verbs = {"create", "delete", "draft", "manage", "send", "update", "write", "configure"}
        ranked = sorted(
            values,
            key=lambda value: (
                len(data_tokens & set(value.split("_"))),
                int(target and bool(effect_verbs & set(value.split("_")))),
                value,
            ),
        )
        if not ranked:
            raise ValueError("Phase 4 composition link references a grant with no known capability")
        return ranked[-1]

    # Frozen V1 links predate explicit endpoint capabilities. This deterministic,
    # provider-catalogue-based adapter preserves their bytes while the generic
    # production detector receives fully explicit observed-flow endpoints.
    links = []
    for link in case.composition_links:
        source_values = capabilities(link.source_grant_id)
        intended_source = sorted(set(source_values) & set(required_capabilities)) or source_values
        links.append(ScenarioDataFlowLink(
            **link.model_dump(mode="python"),
            source_capability=semantic_choice(intended_source, link.data_type, target=False),
            target_capability=semantic_choice(capabilities(link.target_grant_id), link.data_type, target=True),
            description=f"Frozen Phase 4 observed flow {link.link_id}.",
        ))
    result = analyze_provider_qualified_composition(
        grants=grants,
        provider_intents=[ProviderIntentAssignment(
            provider=case.provider,
            principal_id=case.principal_id,
            intended_actions=case.intended_actions,
        )],
        observed_links=links,
        authorized_flows=[],
    )
    return result["unauthorized_paths"]


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


def _qualified_contract(case_id: str, grant, analysis: dict[str, Any]) -> CapabilityContract:
    selected = analysis["least_privilege_plan"]["selected_scopes"]
    catalog = get_catalog(grant.provider)
    capabilities = sorted({cap for scope in selected for cap in catalog.get(scope, ())})
    return CapabilityContract(
        contract_id=f"evaluation-v2-{case_id}-{grant.grant_id}",
        provider=grant.provider,
        principal_id=grant.principal_id,
        source_grant_ids=[grant.grant_id],
        intended_actions=analysis["intended_actions"],
        allowed_scopes=selected,
        allowed_capabilities=capabilities,
        scope_fingerprint=calculate_scope_fingerprint(selected),
        created_at=_FIXED_TIME,
        expires_at=_FIXED_TIME + timedelta(days=1),
        state="active",
        policy_version="1.0.0",
        source_analysis_id=f"evaluation-v2-{case_id}",
        source_evidence_hash="0" * 64,
    )


def evaluate_provider_qualified_case(case, baseline: StaticScopeBaseline | None = None) -> dict[str, Any]:
    """Evaluate a V2 case through production provider-aware services."""
    from app.planner.cross_provider_composition import analyze_provider_qualified_composition

    baseline_result = (baseline or StaticScopeBaseline()).evaluate_qualified(
        provider_intents=case.provider_intents,
        grants=case.grants,
    )
    analyses: dict[tuple[str, str | None], dict[str, Any]] = {}
    matching_grants: dict[tuple[str, str | None], list[Any]] = {}
    for assignment in case.provider_intents:
        key = (assignment.provider, assignment.principal_id)
        matches = [
            grant for grant in case.grants
            if grant.provider == assignment.provider
            and (assignment.principal_id is None or grant.principal_id == assignment.principal_id)
        ]
        matching_grants[key] = matches
        scopes = sorted({scope for grant in matches for scope in grant.granted_scopes})
        analyses[key] = analyze_scope_grant(
            provider=assignment.provider,
            granted_scopes=scopes,
            intended_actions=assignment.intended_actions,
        )

    mock_grants = [
        MockGrant(
            grant_id=grant.grant_id,
            application_name=f"Evaluation {grant.grant_id}",
            provider=grant.provider,
            authority_provider=grant.provider,
            principal_id=grant.principal_id,
            declared_intended_actions=[],
            granted_scopes=grant.granted_scopes,
            observed_scopes=grant.granted_scopes,
            status="active",
            description="Phase 5 deterministic evaluation grant.",
        )
        for grant in case.grants
    ]
    composition = analyze_provider_qualified_composition(
        grants=mock_grants,
        provider_intents=case.provider_intents,
        observed_links=case.observed_links,
        authorized_flows=case.authorized_flows,
    )
    paths = composition["unauthorized_paths"]
    contracts: dict[tuple[str, str, str], CapabilityContract] = {}
    has_unknown = any(value["unknown_intents"] for value in analyses.values())
    has_missing = False
    for key, analysis in analyses.items():
        matches = matching_grants[key]
        if not matches or analysis["missing_capabilities"] or analysis["least_privilege_plan"]["status"] != "complete":
            has_missing = True
            continue
        if len(matches) == 1:
            grant = matches[0]
            contracts[(grant.provider, grant.principal_id, grant.grant_id)] = _qualified_contract(
                case.case_id, grant, analysis
            )

    decisions: list[dict[str, Any]] = []
    executed_scopes: list[list[str]] = []
    if not paths and not has_unknown and not has_missing:
        for attempt in case.runtime_attempts:
            contract_matches = [
                (key, value)
                for key, value in contracts.items()
                if key[2] == attempt.grant_id
            ]
            if len(contract_matches) != 1:
                has_missing = True
                continue
            contract_key, contract = contract_matches[0]
            decision = evaluate_capability_attempt(
                contract,
                attempted_capability=attempt.attempted_capability,
                observed_scopes=attempt.observed_scopes,
                observed_provider=attempt.observed_provider,
                observed_principal_id=attempt.observed_principal_id,
                observed_grant_id=attempt.observed_grant_id,
                now=_FIXED_TIME + timedelta(minutes=1),
            )
            if decision.get("decision") not in {"allow", "block", "quarantine"}:
                raise RuntimeError(f"Malformed gateway decision for case '{case.case_id}'")
            decisions.append(decision)
            if decision["decision"] == "allow":
                executed_scopes.append(sorted(set(attempt.observed_scopes)))
            if decision["state_transition"]:
                contracts[contract_key] = contract.model_copy(update={"state": decision["state_transition"]})

    original = sorted({f"{grant.provider}:{grant.principal_id}:{scope}" for grant in case.grants for scope in grant.granted_scopes})
    selected = sorted({
        f"{provider}:{principal or '*'}:{scope}"
        for (provider, principal), analysis in analyses.items()
        for scope in analysis["least_privilege_plan"]["selected_scopes"]
    })
    required = sorted({
        f"{provider}:{principal or '*'}:{scope}"
        for (provider, principal), analysis in analyses.items()
        for scope in analysis["required_scopes"]
    })
    matched = sorted(set(original) & set(required))
    removed = sorted(set(original) - set(selected))
    missing_scopes = sorted(set(required) - set(original))
    available_capabilities = sorted({
        f"{grant.provider}:{grant.principal_id}:{capability}"
        for grant in case.grants
        for scope in grant.granted_scopes
        for capability in get_catalog(grant.provider).get(scope, ())
    })
    required_capabilities = sorted({
        f"{provider}:{principal or '*'}:{capability}"
        for (provider, principal), analysis in analyses.items()
        for capability in analysis["required_capabilities"]
    })
    missing_capabilities = sorted(set(required_capabilities) - set(available_capabilities))

    if has_unknown:
        outcome = OperationalOutcome.MANUAL_REVIEW
    elif paths:
        outcome = OperationalOutcome.SKIPPED_UNSAFE_COMPOSITION
    elif has_missing:
        outcome = OperationalOutcome.CONTRACT_NOT_CREATED
    elif any(item["decision"] == "quarantine" for item in decisions):
        outcome = OperationalOutcome.QUARANTINED
    elif any(item["decision"] == "block" for item in decisions):
        outcome = OperationalOutcome.BLOCKED
    elif removed:
        outcome = OperationalOutcome.REMEDIATED_THEN_PERMITTED
    else:
        outcome = OperationalOutcome.PERMITTED_SAFE

    unsafe_execution = False
    for decision, scopes in zip(
        [item for item in decisions if item["decision"] == "allow"],
        executed_scopes,
    ):
        contract = contracts.get((
            decision["provider"],
            decision["principal_id"],
            decision["grant_id"] or "",
        ))
        if contract is None or not set(scopes).issubset(set(contract.allowed_scopes)):
            unsafe_execution = True
    if case.ground_truth.classification == "safe":
        contained = None
        normalized = "permitted" if outcome == OperationalOutcome.PERMITTED_SAFE else "prevented"
    else:
        contained = not unsafe_execution and outcome in {
            OperationalOutcome.REMEDIATED_THEN_PERMITTED,
            OperationalOutcome.BLOCKED,
            OperationalOutcome.QUARANTINED,
            OperationalOutcome.CONTRACT_NOT_CREATED,
            OperationalOutcome.SKIPPED_UNSAFE_COMPOSITION,
            OperationalOutcome.MANUAL_REVIEW,
        }
        normalized = "prevented" if contained else "permitted"

    scope_result = {
        "operational_outcome": outcome.value,
        "normalized_result": normalized,
        "unsafe_authority_contained": contained,
        "original_unsafe_authority_executed": unsafe_execution,
        "contract_created": bool(contracts) and not paths and not has_missing,
        "global_cross_provider_contract_created": False,
        "contract_bindings": [
            {"provider": value.provider, "principal_id": value.principal_id, "source_grant_ids": value.source_grant_ids}
            for value in contracts.values()
        ],
        "original_granted_scopes": original,
        "required_scopes": required,
        "matched_scopes": matched,
        "excessive_scopes": removed,
        "missing_scopes": missing_scopes,
        "synthesized_scopes": selected,
        "removed_scopes": removed,
        "required_capabilities": required_capabilities,
        "available_capabilities": available_capabilities,
        "missing_capabilities": missing_capabilities,
        "gateway_decisions": [
            {key: item[key] for key in ("decision", "reason_code", "attempted_capability", "provider", "principal_id", "grant_id", "unexpected_scopes", "missing_scopes")}
            for item in decisions
        ],
        "executed_scopes": executed_scopes,
        "unauthorized_paths": paths,
        "unauthorized_path_count": len(paths),
        "remediation": composition["remediation"],
        "composition": composition,
    }
    expected = "permitted" if case.ground_truth.classification == "safe" else "prevented"
    return {
        "case_id": case.case_id,
        "category": case.category,
        "description": case.description,
        "ground_truth": case.ground_truth.model_dump(mode="json"),
        "expected_normalized_result": expected,
        "baseline": baseline_result.__dict__,
        "scope_sentry": scope_result,
        "baseline_matches_ground_truth": baseline_result.normalized_result == expected,
        "scope_sentry_matches_ground_truth": (
            scope_result["normalized_result"] == expected
            and scope_result["operational_outcome"] == case.ground_truth.expected_outcome.value
            and len(paths) == case.ground_truth.expected_unauthorized_path_count
        ),
    }
