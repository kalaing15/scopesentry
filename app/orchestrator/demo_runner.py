"""End-to-end credential-free ScopeSentry-R demonstration runner."""

from typing import Any, Dict, List, Optional

from app.evidence.service import EvidenceService
from app.gateway.repository import ContractRepository
from app.gateway.service import create_contract, evaluate_runtime_action
from app.planner.analysis_service import analyze_scope_grant
from app.planner.composition_engine import analyze_composition
from app.planner.cross_provider_composition import (
    analyze_provider_qualified_composition,
)
from app.planner.intent_mapper import map_intents_to_scopes
from app.providers.registry import ProviderRegistry
from app.providers.scenario_registry import get_grant, get_scenario
from app.schemas.demo import DemoRunResponse, DemoTimelineEntry, TimelineStatus
from app.schemas.gateway import ContractCreateRequest, GatewayEvaluationRequest
from app.schemas.provider import (
    DemoScenarioDefinition,
    MockGrant,
    ProviderIntentAssignment,
)


class ScenarioNotFoundError(LookupError):
    pass


def _timeline_entry(
    step_number: int,
    stage: str,
    status: TimelineStatus | str,
    summary: str,
    important_values: Optional[Dict[str, Any]] = None,
    evidence_reference=None,
) -> DemoTimelineEntry:
    return DemoTimelineEntry(
        step_number=step_number,
        stage=stage,
        status=status,
        summary=summary,
        important_values=important_values or {},
        evidence_reference=evidence_reference,
    )


def _detect_unauthorized_paths(
    scenario: DemoScenarioDefinition,
    grants: List[MockGrant],
    adapter,
    required_capabilities: List[str],
) -> List[Dict[str, Any]]:
    assignments = scenario.provider_intents or [
        ProviderIntentAssignment(
            provider=grants[0].authority_provider or grants[0].provider,
            intended_actions=scenario.intended_actions,
        )
    ]
    result = analyze_provider_qualified_composition(
        grants=grants,
        provider_intents=assignments,
        observed_links=scenario.data_flow_links,
        authorized_flows=scenario.authorized_flows,
    )
    return result["unauthorized_paths"]


def _evaluate_expectations(
    scenario: DemoScenarioDefinition,
    actual: Dict[str, Any],
) -> bool:
    expected = scenario.expected_values
    checks: List[bool] = []
    fields = expected.model_fields_set
    if "decision" in fields:
        checks.append(actual["gateway_decisions"][:1] == [expected.decision])
    if "decisions" in fields:
        checks.append(
            bool(actual["gateway_decisions"])
            and actual["gateway_decisions"][0] in (expected.decisions or [])
        )
    if "excessive_scopes" in fields:
        checks.append(actual["excessive_scopes"] == expected.excessive_scopes)
    if "excessive_scope" in fields:
        checks.append(expected.excessive_scope in actual["excessive_scopes"])
    if "selected_scopes" in fields:
        checks.append(actual["selected_scopes"] == expected.selected_scopes)
    if "contract_state" in fields:
        checks.append(actual["contract_state"] == expected.contract_state)
    if "unauthorized_path_count" in fields:
        checks.append(
            actual["unauthorized_path_count"]
            == expected.unauthorized_path_count
        )
    if "missing_scope" in fields:
        checks.append(expected.missing_scope in actual["missing_scopes"])
    if "scope_to_add" in fields:
        checks.append(expected.scope_to_add in actual["scopes_to_add"])
    return bool(checks) and all(checks)


class DemoRunner:
    """Run deterministic fixtures through the real internal security services."""

    def __init__(
        self,
        *,
        registry: ProviderRegistry,
        repository: ContractRepository,
        evidence_service: EvidenceService,
    ) -> None:
        self.registry = registry
        self.repository = repository
        self.evidence_service = evidence_service

    def run(self, scenario_id: str) -> DemoRunResponse:
        scenario = get_scenario(scenario_id)
        if scenario is None:
            raise ScenarioNotFoundError(scenario_id)
        if len(scenario.providers) > 1:
            return self._run_multi_provider(scenario)
        adapter = self.registry.get(scenario.provider)
        metadata = adapter.get_metadata()
        grants = [adapter.get_grant(grant_id) for grant_id in scenario.grant_ids]
        combined_scopes = sorted(
            {scope for grant in grants for scope in grant.granted_scopes}
        )
        timeline: List[DemoTimelineEntry] = []

        timeline.append(
            _timeline_entry(
                1,
                "mock_grant_discovery",
                "completed",
                f"Discovered {len(grants)} deterministic simulated grant(s).",
                {
                    "provider": scenario.provider,
                    "grant_ids": [grant.grant_id for grant in grants],
                    "granted_scopes": combined_scopes,
                },
            )
        )

        required_scopes, unknown_intents = map_intents_to_scopes(
            scenario.intended_actions,
            metadata.catalog_provider,
        )
        timeline.append(
            _timeline_entry(
                2,
                "intent_extraction",
                "completed" if not unknown_intents else "manual_review",
                "Mapped declared intentions into normalized scope requirements.",
                {
                    "intended_actions": scenario.intended_actions,
                    "required_scopes": required_scopes,
                    "unknown_intents": unknown_intents,
                },
            )
        )

        analysis = analyze_scope_grant(
            provider=metadata.catalog_provider,
            granted_scopes=combined_scopes,
            intended_actions=scenario.intended_actions,
        )
        analysis_evidence = self.evidence_service.create_record(
            analysis_type="single_grant",
            request={
                "scenario_id": scenario.scenario_id,
                "provider": metadata.catalog_provider,
                "granted_scopes": combined_scopes,
                "intended_actions": scenario.intended_actions,
            },
            result=analysis,
            decision_summary=analysis["recommendation"],
        )
        timeline.append(
            _timeline_entry(
                3,
                "scope_analysis",
                analysis["least_privilege_plan"]["status"],
                analysis["recommendation"],
                {
                    "matched_scopes": analysis["matched_scopes"],
                    "excessive_scopes": analysis["excessive_scopes"],
                    "missing_scopes": analysis["missing_scopes"],
                },
                analysis_evidence,
            )
        )
        graph = analysis["capability_graph"]
        timeline.append(
            _timeline_entry(
                4,
                "capability_graph_construction",
                "completed",
                "Constructed the scope-to-capability proof graph.",
                {
                    "node_count": len(graph["nodes"]),
                    "edge_count": len(graph["edges"]),
                    "required_capabilities": analysis["required_capabilities"],
                    "missing_capabilities": analysis["missing_capabilities"],
                },
            )
        )
        timeline.append(
            _timeline_entry(
                5,
                "exposure_differential",
                "completed",
                "Calculated matched, excessive, and missing authority.",
                {
                    "exposure_score": analysis["exposure_score"],
                    "excessive_capabilities": analysis[
                        "excessive_capabilities"
                    ],
                },
            )
        )
        plan = analysis["least_privilege_plan"]
        timeline.append(
            _timeline_entry(
                6,
                "least_privilege_synthesis",
                plan["status"],
                plan["explanation"],
                {
                    "selected_scopes": plan["selected_scopes"],
                    "scopes_to_remove": plan["scopes_to_remove"],
                    "scopes_to_add": plan["scopes_to_add"],
                },
            )
        )

        composition_summary = None
        unauthorized_paths: List[Dict[str, Any]] = []
        if scenario.data_flow_links:
            composition = analyze_composition(
                metadata.catalog_provider,
                [
                    {
                        "grant_id": grant.grant_id,
                        "granted_scopes": grant.granted_scopes,
                    }
                    for grant in grants
                ],
                scenario.intended_actions,
            )
            unauthorized_paths = _detect_unauthorized_paths(
                scenario,
                grants,
                adapter,
                analysis["required_capabilities"],
            )
            composition_summary = {
                "combined_scopes": composition["combined_scopes"],
                "combined_capabilities": composition[
                    "combined_capabilities"
                ],
                "excessive_capabilities": composition[
                    "excessive_capabilities"
                ],
                "capability_sources": composition["capability_sources"],
                "unauthorized_paths": unauthorized_paths,
                "remediation": [
                    path["remediation"] for path in unauthorized_paths
                ],
            }
            composition_evidence = self.evidence_service.create_record(
                analysis_type="composition",
                request={
                    "scenario_id": scenario.scenario_id,
                    "grants": [grant.grant_id for grant in grants],
                    "data_flow_links": [
                        link.model_dump(mode="json")
                        for link in scenario.data_flow_links
                    ],
                },
                result={
                    "composition": composition,
                    "unauthorized_paths": unauthorized_paths,
                },
                decision_summary=(
                    "Detected an unauthorized composed exfiltration path."
                    if unauthorized_paths
                    else composition["recommendation"]
                ),
            )
            timeline.append(
                _timeline_entry(
                    7,
                    "composition_analysis",
                    "risk_detected" if unauthorized_paths else "completed",
                    (
                        "Detected an observed capability path outside the "
                        "intent-authorized flow policy."
                        if unauthorized_paths
                        else composition["recommendation"]
                    ),
                    {
                        "unauthorized_path_count": len(unauthorized_paths),
                        "excessive_capabilities": composition[
                            "excessive_capabilities"
                        ],
                    },
                    composition_evidence,
                )
            )
        else:
            timeline.append(
                _timeline_entry(
                    7,
                    "composition_analysis",
                    "skipped",
                    "This scenario contains no cross-grant data-flow link.",
                )
            )

        contract = None
        contract_summary = None
        contract_skip_reason = None
        if unauthorized_paths:
            contract_skip_reason = (
                "Contract creation was skipped because composition exposed "
                "an unauthorized exfiltration path."
            )
        elif plan["scopes_to_add"]:
            contract_skip_reason = (
                "Contract creation was skipped until the recommended scopes "
                "are actually granted."
            )
        elif plan["status"] != "complete":
            contract_skip_reason = "The least-privilege plan is not complete."
        else:
            contract = create_contract(
                ContractCreateRequest(
                    provider=metadata.catalog_provider,
                    principal_id=grants[0].principal_id,
                    source_grant_ids=[grant.grant_id for grant in grants],
                    granted_scopes=combined_scopes,
                    intended_actions=scenario.intended_actions,
                    ttl_seconds=3600,
                ),
                repository=self.repository,
                evidence_service=self.evidence_service,
            )
            contract_summary = contract.model_dump(mode="json")

        contract_evidence = (
            self.evidence_service.get_record(contract.source_analysis_id)
            if contract
            else None
        )
        timeline.append(
            _timeline_entry(
                8,
                "contract_creation",
                "completed" if contract else "skipped",
                (
                    "Created an active intent-locked runtime contract."
                    if contract
                    else contract_skip_reason or "Contract was not applicable."
                ),
                (
                    {
                        "contract_id": contract.contract_id,
                        "allowed_scopes": contract.allowed_scopes,
                        "allowed_capabilities": contract.allowed_capabilities,
                    }
                    if contract
                    else {}
                ),
                contract_evidence.reference() if contract_evidence else None,
            )
        )

        gateway_decisions: List[Dict[str, Any]] = []
        if contract and scenario.runtime_attempts:
            for attempt in scenario.runtime_attempts:
                attempt_grant = next(
                    item for item in grants if item.grant_id == attempt.grant_id
                )
                provider_result = adapter.simulate_capability_attempt(
                    attempt.grant_id,
                    attempt.capability,
                )
                decision = evaluate_runtime_action(
                    GatewayEvaluationRequest(
                        contract_id=contract.contract_id,
                        attempted_capability=attempt.capability,
                        observed_scopes=adapter.get_observed_scopes(
                            attempt.grant_id
                        ),
                        resource_reference=attempt.resource_reference,
                        provider=attempt_grant.authority_provider,
                        principal_id=attempt_grant.principal_id,
                        grant_id=attempt_grant.grant_id,
                    ),
                    repository=self.repository,
                    evidence_service=self.evidence_service,
                )
                decision_payload = decision.model_dump(mode="json")
                decision_payload["provider_simulation"] = (
                    provider_result.model_dump(mode="json")
                )
                gateway_decisions.append(decision_payload)
            final_contract = self.repository.get(contract.contract_id)
            assert final_contract is not None
            contract_summary = final_contract.model_dump(mode="json")
            timeline.append(
                _timeline_entry(
                    9,
                    "runtime_action_evaluation",
                    "completed",
                    "Evaluated simulated runtime capability attempts.",
                    {
                        "decisions": [
                            decision["decision"]
                            for decision in gateway_decisions
                        ],
                        "reason_codes": [
                            decision["reason_code"]
                            for decision in gateway_decisions
                        ],
                        "contract_state": final_contract.state,
                    },
                    decision.evidence_reference,
                )
            )
        else:
            timeline.append(
                _timeline_entry(
                    9,
                    "runtime_action_evaluation",
                    "skipped",
                    (
                        "No active contract or runtime attempt was applicable "
                        "to this scenario."
                    ),
                )
            )

        actual_outcome = {
            "result": "evaluated",
            "excessive_scopes": analysis["excessive_scopes"],
            "missing_scopes": analysis["missing_scopes"],
            "selected_scopes": plan["selected_scopes"],
            "scopes_to_add": plan["scopes_to_add"],
            "gateway_decisions": [
                decision["decision"] for decision in gateway_decisions
            ],
            "contract_state": (
                contract_summary["state"] if contract_summary else None
            ),
            "unauthorized_path_count": len(unauthorized_paths),
        }
        passed = _evaluate_expectations(scenario, actual_outcome)
        actual_outcome["result"] = (
            "expected_security_outcome_observed"
            if passed
            else "expected_security_outcome_not_observed"
        )
        completion_evidence = self.evidence_service.create_record(
            analysis_type="demo_completion",
            request={"scenario_id": scenario.scenario_id},
            result={
                "scenario_id": scenario.scenario_id,
                "expected_result": scenario.expected_outcome,
                "actual_result": actual_outcome,
                "passed": passed,
            },
            decision_summary=(
                f"Demo scenario {scenario.scenario_id} "
                f"{'passed' if passed else 'failed'}."
            ),
        )
        verification = self.evidence_service.verify()
        timeline.append(
            _timeline_entry(
                10,
                "evidence_chain_verification",
                "completed" if verification.valid else "failed",
                verification.message,
                {
                    "records_checked": verification.records_checked,
                    "head_hash": verification.head_hash,
                },
                completion_evidence,
            )
        )

        analysis_summary = {
            "provider": scenario.provider,
            "catalog_provider": metadata.catalog_provider,
            "granted_scopes": analysis["granted_scopes"],
            "required_scopes": analysis["required_scopes"],
            "matched_scopes": analysis["matched_scopes"],
            "excessive_scopes": analysis["excessive_scopes"],
            "missing_scopes": analysis["missing_scopes"],
            "required_capabilities": analysis["required_capabilities"],
            "granted_capabilities": analysis["granted_capabilities"],
            "missing_capabilities": analysis["missing_capabilities"],
            "excessive_capabilities": analysis["excessive_capabilities"],
            "exposure_score": analysis["exposure_score"],
            "least_privilege_plan": plan,
            "recommendation": analysis["recommendation"],
        }
        return DemoRunResponse(
            scenario_id=scenario.scenario_id,
            scenario_name=scenario.scenario_name,
            expected_outcome=scenario.expected_outcome,
            actual_outcome=actual_outcome,
            passed=passed,
            timeline=timeline,
            analysis_summary=analysis_summary,
            composition_summary=composition_summary,
            contract_summary=contract_summary,
            gateway_decisions=gateway_decisions,
            evidence_chain_valid=verification.valid,
            providers=scenario.providers,
            provider_intents=scenario.provider_intents,
        )

    def _run_multi_provider(
        self, scenario: DemoScenarioDefinition
    ) -> DemoRunResponse:
        """Run provider-qualified scenarios using isolated per-grant contracts."""
        grants = [get_grant(grant_id) for grant_id in scenario.grant_ids]
        timeline: List[DemoTimelineEntry] = [
            _timeline_entry(
                1,
                "mock_grant_discovery",
                "completed",
                f"Discovered {len(grants)} provider-qualified synthetic grants.",
                {
                    "providers": scenario.providers,
                    "grants": [
                        {
                            "provider": grant.authority_provider,
                            "principal_id": grant.principal_id,
                            "grant_id": grant.grant_id,
                        }
                        for grant in grants
                    ],
                },
            )
        ]
        analyses: Dict[tuple[str, str], Dict[str, Any]] = {}
        boundaries: List[tuple[ProviderIntentAssignment, tuple[str, str], List[MockGrant]]] = []
        for assignment in scenario.provider_intents:
            candidates = [
                grant
                for grant in grants
                if grant.authority_provider == assignment.provider
                and (
                    assignment.principal_id is None
                    or grant.principal_id == assignment.principal_id
                )
            ]
            principals = {grant.principal_id for grant in candidates}
            if assignment.principal_id is not None:
                principal_id = assignment.principal_id
            elif len(principals) == 1:
                principal_id = next(iter(principals))
            else:
                raise ValueError(
                    "A provider-intent assignment must resolve to exactly one provider/principal boundary"
                )
            provider_grants = [grant for grant in candidates if grant.principal_id == principal_id]
            key = (assignment.provider, principal_id)
            if key in analyses:
                raise ValueError(f"Duplicate provider-intent boundary {key}")
            scopes = sorted(
                {scope for grant in provider_grants for scope in grant.granted_scopes}
            )
            analyses[key] = analyze_scope_grant(
                provider=assignment.provider,
                granted_scopes=scopes,
                intended_actions=assignment.intended_actions,
            )
            boundaries.append((assignment, key, provider_grants))
        primary_provider, primary_principal = boundaries[0][1]
        primary = analyses[(primary_provider, primary_principal)]
        provider_analysis_items = [
            {
                "provider": provider,
                "principal_id": principal,
                "analysis": analyses[(provider, principal)],
            }
            for provider, principal in sorted(analyses)
        ]
        timeline.append(
            _timeline_entry(
                2,
                "intent_extraction",
                "manual_review"
                if any(item["unknown_intents"] for item in analyses.values())
                else "completed",
                "Mapped each intended action only within its canonical provider namespace.",
                {
                    "provider_intents": [
                        item.model_dump(mode="json")
                        for item in scenario.provider_intents
                    ]
                },
            )
        )
        analysis_evidence = self.evidence_service.create_record(
            analysis_type="composition",
            request={
                "scenario_id": scenario.scenario_id,
                "providers": scenario.providers,
                "grants": [grant.model_dump(mode="json") for grant in grants],
                "provider_intents": [
                    item.model_dump(mode="json") for item in scenario.provider_intents
                ],
            },
            result={"provider_analyses": provider_analysis_items},
            decision_summary="Completed provider-isolated scope analyses.",
        )
        timeline.extend(
            [
                _timeline_entry(
                    3,
                    "scope_analysis",
                    primary["least_privilege_plan"]["status"],
                    "Analyzed each provider boundary independently.",
                    {"provider_analyses": provider_analysis_items},
                    analysis_evidence,
                ),
                _timeline_entry(
                    4,
                    "capability_graph_construction",
                    "completed",
                    "Constructed provider-qualified capability provenance.",
                    {
                        "providers": scenario.providers,
                        "required_capabilities": [
                            {
                                "provider": item["provider"],
                                "principal_id": item["principal_id"],
                                "capabilities": item["analysis"]["required_capabilities"],
                            }
                            for item in provider_analysis_items
                        ],
                    },
                ),
                _timeline_entry(
                    5,
                    "exposure_differential",
                    "completed",
                    "Calculated exposure separately within each provider.",
                    {
                        "excessive_scopes": [
                            {
                                "provider": item["provider"],
                                "principal_id": item["principal_id"],
                                "scopes": item["analysis"]["excessive_scopes"],
                            }
                            for item in provider_analysis_items
                        ]
                    },
                ),
                _timeline_entry(
                    6,
                    "least_privilege_synthesis",
                    "complete"
                    if all(value["least_privilege_plan"]["status"] == "complete" for value in analyses.values())
                    else "incomplete",
                    "Synthesized isolated provider-specific scope plans.",
                    {
                        "selected_scopes": [
                            {
                                "provider": item["provider"],
                                "principal_id": item["principal_id"],
                                "scopes": item["analysis"]["least_privilege_plan"]["selected_scopes"],
                            }
                            for item in provider_analysis_items
                        ]
                    },
                ),
            ]
        )
        composition = analyze_provider_qualified_composition(
            grants=grants,
            provider_intents=scenario.provider_intents,
            observed_links=scenario.data_flow_links,
            authorized_flows=scenario.authorized_flows,
        )
        unauthorized_paths = composition["unauthorized_paths"]
        composition_evidence = self.evidence_service.create_record(
            analysis_type="composition",
            request={
                "scenario_id": scenario.scenario_id,
                "observed_links": [item.model_dump(mode="json") for item in scenario.data_flow_links],
                "authorized_flows": [item.model_dump(mode="json") for item in scenario.authorized_flows],
            },
            result=composition,
            decision_summary=(
                "Detected provider-qualified unauthorized observed flow."
                if unauthorized_paths
                else "Every observed flow matched an exact flow authorization."
            ),
        )
        timeline.append(
            _timeline_entry(
                7,
                "composition_analysis",
                "risk_detected" if unauthorized_paths else "completed",
                "Compared observed flows with exact intent-authorized flow contracts.",
                {
                    "unauthorized_path_count": len(unauthorized_paths),
                    "cross_provider": any(item["cross_provider"] for item in composition["observed_paths"]),
                },
                composition_evidence,
            )
        )

        contracts: Dict[tuple[str, str, str], Any] = {}
        if not unauthorized_paths:
            for assignment, key, provider_grants in boundaries:
                analysis = analyses[key]
                plan = analysis["least_privilege_plan"]
                if (
                    len(provider_grants) == 1
                    and not analysis["unknown_intents"]
                    and not analysis["missing_capabilities"]
                    and not plan["scopes_to_add"]
                    and plan["status"] == "complete"
                ):
                    grant = provider_grants[0]
                    contract = create_contract(
                        ContractCreateRequest(
                            provider=assignment.provider,
                            principal_id=grant.principal_id,
                            source_grant_ids=[grant.grant_id],
                            granted_scopes=grant.granted_scopes,
                            intended_actions=assignment.intended_actions,
                            ttl_seconds=3600,
                        ),
                        repository=self.repository,
                        evidence_service=self.evidence_service,
                    )
                    contracts[(
                        grant.authority_provider or grant.provider,
                        grant.principal_id,
                        grant.grant_id,
                    )] = contract
        timeline.append(
            _timeline_entry(
                8,
                "contract_creation",
                "completed" if contracts else "skipped",
                (
                    f"Created {len(contracts)} isolated provider/grant contract(s)."
                    if contracts
                    else "No executable contract was created across provider boundaries."
                ),
                {
                    "global_cross_provider_contract_created": False,
                    "contract_bindings": [
                        {
                            "provider": value.provider,
                            "principal_id": value.principal_id,
                            "source_grant_ids": value.source_grant_ids,
                        }
                        for value in contracts.values()
                    ],
                },
            )
        )
        gateway_decisions: List[Dict[str, Any]] = []
        if contracts and scenario.runtime_attempts:
            for attempt in scenario.runtime_attempts:
                grant = get_grant(attempt.grant_id)
                contract = contracts.get((
                    grant.authority_provider or grant.provider,
                    grant.principal_id,
                    grant.grant_id,
                ))
                if contract is None:
                    continue
                adapter = self.registry.get(grant.provider)
                decision = evaluate_runtime_action(
                    GatewayEvaluationRequest(
                        contract_id=contract.contract_id,
                        attempted_capability=attempt.capability,
                        observed_scopes=adapter.get_observed_scopes(grant.grant_id),
                        resource_reference=attempt.resource_reference,
                        provider=grant.authority_provider,
                        principal_id=grant.principal_id,
                        grant_id=grant.grant_id,
                    ),
                    repository=self.repository,
                    evidence_service=self.evidence_service,
                )
                gateway_decisions.append(decision.model_dump(mode="json"))
        timeline.append(
            _timeline_entry(
                9,
                "runtime_action_evaluation",
                "completed" if gateway_decisions else "skipped",
                "Evaluated runtime actions only against their stored provider/grant contracts.",
                {
                    "decisions": [item["decision"] for item in gateway_decisions],
                    "reason_codes": [item["reason_code"] for item in gateway_decisions],
                },
            )
        )
        actual = {
            "result": "evaluated",
            "excessive_scopes": primary["excessive_scopes"],
            "missing_scopes": primary["missing_scopes"],
            "selected_scopes": primary["least_privilege_plan"]["selected_scopes"],
            "scopes_to_add": primary["least_privilege_plan"]["scopes_to_add"],
            "gateway_decisions": [item["decision"] for item in gateway_decisions],
            "contract_state": (
                "active" if contracts and all(self.repository.get(value.contract_id).state == "active" for value in contracts.values()) else None
            ),
            "unauthorized_path_count": len(unauthorized_paths),
        }
        passed = _evaluate_expectations(scenario, actual)
        actual["result"] = "expected_security_outcome_observed" if passed else "expected_security_outcome_not_observed"
        completion = self.evidence_service.create_record(
            analysis_type="demo_completion",
            request={"scenario_id": scenario.scenario_id, "providers": scenario.providers},
            result={"actual_result": actual, "passed": passed},
            decision_summary=f"Multi-provider demo {scenario.scenario_id} {'passed' if passed else 'failed'}.",
        )
        verification = self.evidence_service.verify()
        timeline.append(
            _timeline_entry(
                10,
                "evidence_chain_verification",
                "completed" if verification.valid else "failed",
                verification.message,
                {"records_checked": verification.records_checked, "head_hash": verification.head_hash},
                completion,
            )
        )
        qualified_capabilities = [
            {
                "provider": node["provider"],
                "principal_id": node["principal_id"],
                "grant_id": node["grant_id"],
                "scope": node["scope"],
                "capability": node["capability"],
            }
            for node in composition["composition_graph"]["nodes"]
            if node["node_type"] == "capability"
        ]
        summary = {
            "provider": scenario.provider,
            "catalog_provider": primary_provider,
            "granted_scopes": primary["granted_scopes"],
            "required_scopes": primary["required_scopes"],
            "matched_scopes": primary["matched_scopes"],
            "excessive_scopes": primary["excessive_scopes"],
            "missing_scopes": primary["missing_scopes"],
            "required_capabilities": primary["required_capabilities"],
            "granted_capabilities": primary["granted_capabilities"],
            "missing_capabilities": primary["missing_capabilities"],
            "excessive_capabilities": primary["excessive_capabilities"],
            "exposure_score": primary["exposure_score"],
            "least_privilege_plan": primary["least_privilege_plan"],
            "recommendation": primary["recommendation"],
            "providers": scenario.providers,
            "provider_analyses": provider_analysis_items,
            "qualified_capabilities": qualified_capabilities,
        }
        contract_summary = (
            {
                "state": actual["contract_state"],
                "global_cross_provider_contract_created": False,
                "contracts": [value.model_dump(mode="json") for value in contracts.values()],
            }
            if contracts
            else None
        )
        return DemoRunResponse(
            scenario_id=scenario.scenario_id,
            scenario_name=scenario.scenario_name,
            expected_outcome=scenario.expected_outcome,
            actual_outcome=actual,
            passed=passed,
            timeline=timeline,
            analysis_summary=summary,
            composition_summary=composition,
            contract_summary=contract_summary,
            gateway_decisions=gateway_decisions,
            evidence_chain_valid=verification.valid,
            providers=scenario.providers,
            provider_intents=scenario.provider_intents,
        )
