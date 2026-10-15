"""Reusable capability-contract and runtime-enforcement services."""

from typing import Any, Dict, List

from app.evidence.service import EvidenceService
from app.gateway.contracts import (
    build_contract_payload,
    finalize_contract,
    normalize_scopes,
)
from app.gateway.policy_engine import evaluate_capability_attempt
from app.gateway.repository import ContractRepository
from app.planner.analysis_service import (
    UnsupportedAnalysisProviderError,
    analyze_scope_grant,
)
from app.providers.mock.catalog import get_catalog
from app.schemas.gateway import (
    CapabilityContract,
    ContractCreateRequest,
    GatewayEvaluationRequest,
    GatewayEvaluationResponse,
)


class ContractPlanConflictError(RuntimeError):
    def __init__(self, detail: Dict[str, Any]):
        super().__init__(detail.get("message", "Contract plan conflict."))
        self.detail = detail


class UnknownContractError(LookupError):
    pass


def _capabilities_for_scopes(provider: str, scopes: List[str]) -> List[str]:
    catalog = get_catalog(provider)
    return sorted(
        {
            capability
            for scope in scopes
            for capability in catalog.get(scope, [])
        }
    )


def create_contract(
    request: ContractCreateRequest,
    *,
    repository: ContractRepository,
    evidence_service: EvidenceService,
) -> CapabilityContract:
    analysis = analyze_scope_grant(
        provider=request.provider,
        granted_scopes=request.granted_scopes,
        intended_actions=request.intended_actions,
    )
    plan = analysis["least_privilege_plan"]
    unknown_intents = analysis["unknown_intents"]
    if unknown_intents or plan["status"] != "complete":
        raise ContractPlanConflictError(
            {
                "message": (
                    "A capability contract cannot be created until the "
                    "least-privilege plan is complete and all intentions "
                    "are recognized."
                ),
                "plan_status": plan["status"],
                "unknown_intents": unknown_intents,
                "uncovered_capabilities": plan["uncovered_capabilities"],
                "explanation": plan["explanation"],
            }
        )

    provider = analysis["provider"]
    selected_scopes = normalize_scopes(plan["selected_scopes"])
    allowed_capabilities = _capabilities_for_scopes(provider, selected_scopes)
    required_capabilities = set(analysis["required_capabilities"])
    if (
        plan["uncovered_capabilities"]
        or not required_capabilities.issubset(allowed_capabilities)
    ):
        raise ContractPlanConflictError(
            {
                "message": (
                    "The synthesized plan does not cover every required "
                    "capability."
                ),
                "plan_status": "incomplete",
                "uncovered_capabilities": sorted(
                    required_capabilities - set(allowed_capabilities)
                ),
            }
        )

    contract_payload = build_contract_payload(
        provider=provider,
        intended_actions=request.intended_actions,
        allowed_scopes=selected_scopes,
        allowed_capabilities=allowed_capabilities,
        ttl_seconds=request.ttl_seconds,
    )
    evidence_reference = evidence_service.create_record(
        analysis_type="contract_created",
        request=request,
        result={"contract": contract_payload, "analysis": analysis},
        decision_summary=(
            f"Created active least-privilege contract "
            f"{contract_payload['contract_id']}."
        ),
    )
    contract = finalize_contract(
        contract_payload,
        source_analysis_id=evidence_reference.analysis_id,
        source_evidence_hash=evidence_reference.record_hash,
    )
    return repository.create(contract)


def revoke_contract(
    contract_id: str,
    *,
    repository: ContractRepository,
    evidence_service: EvidenceService,
) -> CapabilityContract:
    current = repository.get(contract_id)
    if current is None:
        raise UnknownContractError(contract_id)
    if current.state != "revoked":
        result = current.model_dump(mode="python")
        result["state"] = "revoked"
        evidence_service.create_record(
            analysis_type="contract_revoked",
            request={"contract_id": contract_id},
            result=result,
            decision_summary=f"Revoked capability contract {contract_id}.",
        )
    revoked = repository.revoke(contract_id)
    assert revoked is not None
    return revoked


def evaluate_runtime_action(
    request: GatewayEvaluationRequest,
    *,
    repository: ContractRepository,
    evidence_service: EvidenceService,
) -> GatewayEvaluationResponse:
    contract = repository.get(request.contract_id)
    if contract is None:
        raise UnknownContractError(request.contract_id)

    outcome = evaluate_capability_attempt(
        contract,
        attempted_capability=request.attempted_capability,
        observed_scopes=request.observed_scopes,
    )
    transition = outcome.pop("state_transition")
    if transition is not None:
        transition_type = {
            "quarantined": "contract_quarantined",
            "expired": "contract_expired",
        }[transition]
        evidence_service.create_record(
            analysis_type=transition_type,
            request=request,
            result={
                "contract_id": contract.contract_id,
                "previous_state": contract.state,
                "new_state": transition,
                "reason_code": outcome["reason_code"],
                "unexpected_scopes": outcome["unexpected_scopes"],
                "missing_scopes": outcome["missing_scopes"],
            },
            decision_summary=(
                f"Contract {contract.contract_id} transitioned from "
                f"{contract.state} to {transition}."
            ),
        )
        updated = repository.update_state(contract.contract_id, transition)
        assert updated is not None

    decision_summary = (
        f"Gateway {outcome['decision']} decision for capability "
        f"'{outcome['attempted_capability']}' under contract "
        f"{contract.contract_id}: {outcome['reason_code']}."
    )
    evidence_reference = evidence_service.create_record(
        analysis_type="gateway_decision",
        request=request,
        result=outcome,
        decision_summary=decision_summary,
    )
    return GatewayEvaluationResponse(
        **outcome,
        evidence_reference=evidence_reference,
    )
