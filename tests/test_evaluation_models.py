from copy import deepcopy

import pytest
from pydantic import ValidationError

from app.evaluation.corpus import CORPUS, corpus_hash, get_evaluation_corpus
from app.evaluation.schemas import EvaluationCase, EvaluationCorpus


def _payload():
    return CORPUS.cases[0].model_dump(mode="json")


def test_corpus_has_approved_balance_and_deterministic_order():
    corpus = get_evaluation_corpus()
    assert len(corpus.cases) == 24
    assert sum(case.ground_truth.classification == "safe" for case in corpus.cases) == 8
    assert sum(case.ground_truth.classification == "unsafe" for case in corpus.cases) == 16
    assert [case.case_id for case in corpus.cases] == [case.case_id for case in get_evaluation_corpus().cases]


def test_corpus_hash_is_stable_and_ignores_runtime_metadata():
    first = corpus_hash()
    second = corpus_hash(get_evaluation_corpus())
    assert first == second
    assert len(first) == 64
    unrelated_timing = {"timestamp": "later", "median": 999}
    assert unrelated_timing and corpus_hash() == first


def test_duplicate_case_ids_are_rejected():
    case = _payload()
    with pytest.raises(ValidationError, match="case IDs must be unique"):
        EvaluationCorpus(version="test", cases=[case, case])


def test_missing_ground_truth_is_rejected():
    payload = _payload()
    payload.pop("ground_truth")
    with pytest.raises(ValidationError):
        EvaluationCase.model_validate(payload)


def test_invalid_category_is_rejected():
    payload = _payload()
    payload["category"] = "invented"
    with pytest.raises(ValidationError):
        EvaluationCase.model_validate(payload)


@pytest.mark.parametrize("scope", ["", "   ", "bad scope", "bad\x00scope"])
def test_invalid_scope_values_are_rejected(scope):
    payload = _payload()
    payload["grants"][0]["granted_scopes"] = [scope]
    with pytest.raises(ValidationError):
        EvaluationCase.model_validate(payload)


def test_unknown_static_scope_requires_explicit_case_flag():
    payload = _payload()
    payload["grants"][0]["granted_scopes"] = ["unknown.scope"]
    with pytest.raises(ValidationError, match="unknown catalogue scopes"):
        EvaluationCase.model_validate(payload)
    payload["allow_unknown_scopes"] = True
    assert EvaluationCase.model_validate(payload).allow_unknown_scopes


def test_invalid_runtime_capability_is_rejected():
    payload = _payload()
    payload["runtime_attempts"][0]["attempted_capability"] = "invented_capability"
    with pytest.raises(ValidationError, match="unsupported capabilities"):
        EvaluationCase.model_validate(payload)


def test_duplicate_grants_and_invalid_link_references_are_rejected():
    payload = _payload()
    payload["grants"].append(deepcopy(payload["grants"][0]))
    with pytest.raises(ValidationError, match="duplicate grant"):
        EvaluationCase.model_validate(payload)

    payload = _payload()
    payload["composition_links"] = [{"link_id": "link", "source_grant_id": "missing", "target_grant_id": payload["grants"][0]["grant_id"], "data_type": "content"}]
    with pytest.raises(ValidationError, match="unknown source grant"):
        EvaluationCase.model_validate(payload)


def test_runtime_attempt_unknown_grant_reference_is_rejected():
    payload = _payload()
    payload["runtime_attempts"][0]["grant_id"] = "missing-grant"
    with pytest.raises(ValidationError, match="runtime attempt references unknown"):
        EvaluationCase.model_validate(payload)


def test_duplicate_link_ids_and_self_links_are_rejected():
    payload = CORPUS.cases[20].model_dump(mode="json")
    payload["composition_links"].append(deepcopy(payload["composition_links"][0]))
    with pytest.raises(ValidationError, match="duplicate link"):
        EvaluationCase.model_validate(payload)
    payload = CORPUS.cases[20].model_dump(mode="json")
    payload["composition_links"][0]["target_grant_id"] = payload["composition_links"][0]["source_grant_id"]
    with pytest.raises(ValidationError, match="self-referencing"):
        EvaluationCase.model_validate(payload)
