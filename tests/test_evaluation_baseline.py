import pytest

from app.evaluation.baseline import StaticScopeBaseline
from app.evaluation.corpus import CORPUS
from app.evaluation.engine import evaluate_case, evaluate_scope_sentry


def test_exact_scope_covers_itself():
    assert StaticScopeBaseline.scope_covers("google", "drive.readonly", "drive.readonly")


def test_broader_catalogue_scope_covers_narrower_scope():
    assert StaticScopeBaseline.scope_covers("google", "drive.full", "drive.readonly")


def test_narrower_scope_does_not_cover_broader_scope():
    assert not StaticScopeBaseline.scope_covers("google", "drive.readonly", "drive.full")


def test_unrelated_and_unknown_scopes_do_not_cover_required_scope():
    assert not StaticScopeBaseline.scope_covers("google", "gmail.send", "drive.readonly")
    assert not StaticScopeBaseline.scope_covers("google", "unknown.scope", "drive.readonly")


def test_exact_safe_case_is_permitted():
    result = evaluate_case(CORPUS.cases[0])
    assert result["baseline"]["normalized_result"] == "permitted"
    assert result["scope_sentry"]["operational_outcome"] == "permitted_safe"


def test_excessive_scope_exposes_baseline_limitation_but_is_remediated():
    case = next(case for case in CORPUS.cases if case.case_id == "excessive-drive-full")
    result = evaluate_case(case)
    assert result["baseline"]["normalized_result"] == "permitted"
    assert result["scope_sentry"]["operational_outcome"] == "remediated_then_permitted"
    assert result["scope_sentry"]["unsafe_authority_contained"] is True
    assert result["scope_sentry"]["original_unsafe_authority_executed"] is False
    assert result["scope_sentry"]["executed_scopes"] == [["drive.readonly"]]


def test_missing_scope_is_prevented_by_both_systems():
    case = next(case for case in CORPUS.cases if case.case_id == "missing-drive-read")
    result = evaluate_case(case)
    assert result["baseline"]["normalized_result"] == "prevented"
    assert result["scope_sentry"]["operational_outcome"] == "contract_not_created"
    assert result["scope_sentry"]["contract_created"] is False


def test_runtime_drift_and_composition_are_baseline_limitations():
    for case_id, expected in (("known-runtime-drift", "quarantined"), ("drive-email-exfiltration", "skipped_unsafe_composition")):
        case = next(case for case in CORPUS.cases if case.case_id == case_id)
        result = evaluate_case(case)
        assert result["baseline"]["normalized_result"] == "permitted"
        assert result["scope_sentry"]["operational_outcome"] == expected
        assert result["scope_sentry"]["unsafe_authority_contained"] is True


def test_baseline_and_scope_sentry_receive_same_case_inputs():
    case = CORPUS.cases[7]
    result = evaluate_case(case)
    assert result["baseline"]["granted_scopes"] == result["scope_sentry"]["original_granted_scopes"]
    assert result["baseline"]["required_scopes"] == result["scope_sentry"]["required_scopes"]


def test_unknown_gateway_decision_is_an_error_not_a_safe_allow(monkeypatch):
    monkeypatch.setattr(
        "app.evaluation.engine.evaluate_capability_attempt",
        lambda *args, **kwargs: {"decision": "unknown"},
    )
    with pytest.raises(RuntimeError, match="Malformed gateway decision"):
        evaluate_scope_sentry(CORPUS.cases[0])
