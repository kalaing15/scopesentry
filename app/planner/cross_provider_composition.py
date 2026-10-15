"""Generic explicit-flow analysis with provider-qualified provenance."""

from collections import defaultdict
from typing import Any, Iterable

from app.planner.provider_identity import (
    CapabilityIdentity,
    GrantIdentity,
    ScopeIdentity,
    identity_node_id,
)
from app.providers.catalog import get_catalog, resolve_authority_provider_id
from app.providers.intent_catalog import map_provider_intents
from app.schemas.provider import (
    AuthorizedFlow,
    MockGrant,
    ProviderIntentAssignment,
    ScenarioDataFlowLink,
)


def _capability_sources(grant: MockGrant) -> dict[str, list[str]]:
    catalog = get_catalog(grant.authority_provider or grant.provider)
    sources: dict[str, list[str]] = defaultdict(list)
    for scope in sorted(grant.granted_scopes):
        for capability in catalog.get(scope, ()):
            sources[capability].append(scope)
    return {key: sorted(value) for key, value in sorted(sources.items())}


def _authorization_key(value: AuthorizedFlow) -> tuple[str, ...]:
    return (
        value.source_provider,
        value.source_principal_id,
        value.source_grant_id,
        value.source_capability,
        value.data_type,
        value.target_provider,
        value.target_principal_id,
        value.target_grant_id,
        value.target_capability,
    )


def analyze_provider_qualified_composition(
    *,
    grants: Iterable[MockGrant],
    provider_intents: Iterable[ProviderIntentAssignment],
    observed_links: Iterable[ScenarioDataFlowLink],
    authorized_flows: Iterable[AuthorizedFlow],
) -> dict[str, Any]:
    grant_list = sorted(
        list(grants),
        key=lambda item: (
            item.authority_provider or item.provider,
            item.principal_id,
            item.grant_id,
        ),
    )
    grants_by_identity: dict[GrantIdentity, MockGrant] = {}
    identities_by_grant_id: dict[str, list[GrantIdentity]] = defaultdict(list)
    for grant in grant_list:
        canonical = resolve_authority_provider_id(
            grant.authority_provider or grant.provider
        )
        identity = GrantIdentity(canonical, grant.principal_id, grant.grant_id)
        if identity in grants_by_identity:
            raise ValueError(f"Duplicate complete grant identity: {identity}")
        grants_by_identity[identity] = grant
        identities_by_grant_id[grant.grant_id].append(identity)

    intent_requirements: dict[tuple[str, str | None], dict[str, Any]] = {}
    for assignment in provider_intents:
        provider = resolve_authority_provider_id(assignment.provider)
        required_scopes, unknown = map_provider_intents(
            provider, assignment.intended_actions
        )
        catalog = get_catalog(provider)
        required_capabilities = sorted(
            {capability for scope in required_scopes for capability in catalog.get(scope, ())}
        )
        key = (provider, assignment.principal_id)
        if key in intent_requirements:
            raise ValueError(f"Duplicate provider-intent boundary {key}")
        intent_requirements[key] = {
            "provider": provider,
            "principal_id": assignment.principal_id,
            "intended_actions": list(assignment.intended_actions),
            "required_scopes": required_scopes,
            "required_capabilities": required_capabilities,
            "unknown_intents": unknown,
        }

    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    capability_nodes: dict[tuple[GrantIdentity, str], list[str]] = defaultdict(list)
    capability_sources: dict[GrantIdentity, dict[str, list[str]]] = {}
    for grant in grant_list:
        identity = GrantIdentity(
            resolve_authority_provider_id(grant.authority_provider or grant.provider),
            grant.principal_id,
            grant.grant_id,
        )
        grant_node = identity_node_id("grant", identity)
        nodes[grant_node] = {
            "id": grant_node,
            "node_type": "grant",
            "provider": identity.provider,
            "principal_id": identity.principal_id,
            "grant_id": identity.grant_id,
        }
        sources = _capability_sources(grant)
        capability_sources[identity] = sources
        for scope in sorted(grant.granted_scopes):
            scope_identity = ScopeIdentity(
                identity.provider, identity.principal_id, identity.grant_id, scope
            )
            scope_node = identity_node_id("scope", scope_identity)
            nodes[scope_node] = {
                "id": scope_node,
                "node_type": "scope",
                "provider": identity.provider,
                "principal_id": identity.principal_id,
                "grant_id": identity.grant_id,
                "scope": scope,
            }
            edges.append({"source": grant_node, "target": scope_node, "relation": "HAS_SCOPE"})
            for capability in get_catalog(identity.provider).get(scope, ()):
                cap_identity = CapabilityIdentity(
                    identity.provider,
                    identity.principal_id,
                    identity.grant_id,
                    scope,
                    capability,
                )
                cap_node = identity_node_id("capability", cap_identity)
                nodes[cap_node] = {
                    "id": cap_node,
                    "node_type": "capability",
                    "provider": identity.provider,
                    "principal_id": identity.principal_id,
                    "grant_id": identity.grant_id,
                    "scope": scope,
                    "source_scope": scope,
                    "capability": capability,
                }
                capability_nodes[(identity, capability)].append(cap_node)
                edges.append({"source": scope_node, "target": cap_node, "relation": "ENABLES"})

    authorization_keys = {_authorization_key(item) for item in authorized_flows}

    def resolve_endpoint(link: ScenarioDataFlowLink, endpoint: str) -> GrantIdentity:
        grant_id = getattr(link, f"{endpoint}_grant_id")
        provider = getattr(link, f"{endpoint}_provider")
        principal = getattr(link, f"{endpoint}_principal_id")
        candidates = identities_by_grant_id.get(grant_id, [])
        if provider is not None:
            candidates = [
                identity for identity in candidates
                if identity.provider == provider and identity.principal_id == principal
            ]
        if len(candidates) != 1:
            qualifier = "qualified" if provider is not None else "unqualified"
            raise ValueError(
                f"Observed link '{link.link_id}' has an unknown or ambiguous {qualifier} {endpoint} grant reference"
            )
        return candidates[0]

    observed_paths: list[dict[str, Any]] = []
    unauthorized_paths: list[dict[str, Any]] = []
    for link in sorted(observed_links, key=lambda item: item.link_id):
        if link.source_capability is None or link.target_capability is None:
            raise ValueError(f"Observed link '{link.link_id}' must declare source and target capabilities")
        source = resolve_endpoint(link, "source")
        target = resolve_endpoint(link, "target")
        if link.source_capability not in capability_sources[source]:
            raise ValueError(f"Observed link '{link.link_id}' source capability is not enabled by its grant")
        if link.target_capability not in capability_sources[target]:
            raise ValueError(f"Observed link '{link.link_id}' target capability is not enabled by its grant")
        key = (
            source.provider, source.principal_id, source.grant_id,
            link.source_capability, link.data_type,
            target.provider, target.principal_id, target.grant_id,
            link.target_capability,
        )
        authorized = key in authorization_keys
        path = {
            "link_id": link.link_id,
            "source_provider": source.provider,
            "source_principal_id": source.principal_id,
            "source_grant_id": source.grant_id,
            "source_capability": link.source_capability,
            "data_type": link.data_type,
            "target_provider": target.provider,
            "target_principal_id": target.principal_id,
            "target_grant_id": target.grant_id,
            "target_capability": link.target_capability,
            "authorized_by_intent": authorized,
            "cross_provider": source.provider != target.provider,
            "remediation": (
                "No remediation is required; the observed flow exactly matches an intent-authorized flow contract."
                if authorized
                else f"Break the data-flow link '{link.link_id}' or remove unnecessary target authority '{link.target_capability}' from provider '{target.provider}'."
            ),
        }
        observed_paths.append(path)
        if not authorized:
            unauthorized_paths.append(path)
        for source_node in capability_nodes[(source, link.source_capability)]:
            for target_node in capability_nodes[(target, link.target_capability)]:
                edges.append({
                    "source": source_node,
                    "target": target_node,
                    "relation": "OBSERVED_FLOW",
                    "link_id": link.link_id,
                    "data_type": link.data_type,
                    "authorized": authorized,
                })

    return {
        "providers": sorted({identity.provider for identity in grants_by_identity}),
        "grant_identities": [
            {"provider": item.provider, "principal_id": item.principal_id, "grant_id": item.grant_id}
            for item in sorted(grants_by_identity)
        ],
        "provider_intent_requirements": [
            intent_requirements[key]
            for key in sorted(
                intent_requirements,
                key=lambda item: (item[0], item[1] or ""),
            )
        ],
        "observed_paths": observed_paths,
        "unauthorized_paths": unauthorized_paths,
        "remediation": sorted({item["remediation"] for item in unauthorized_paths}),
        "composition_graph": {
            "nodes": [nodes[key] for key in sorted(nodes)],
            "edges": sorted(edges, key=lambda item: (item["source"], item["target"], item["relation"], item.get("link_id", ""))),
        },
    }
