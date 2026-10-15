from typing import List, TypedDict

from app.providers.mock.catalog import (
    DEFAULT_RISK_WEIGHT,
    get_risk_weights,
)


class ExposureDifferential(TypedDict):
    matched_scopes: List[str]
    excessive_scopes: List[str]
    missing_scopes: List[str]
    exposure_score: float


def calculate_exposure_differential(
    granted_scopes: List[str],
    required_scopes: List[str],
    provider: str = "google",
) -> ExposureDifferential:
    risk_weights = get_risk_weights(provider)
    granted = set(granted_scopes)
    required = set(required_scopes)

    matched_scopes = sorted(granted & required)
    excessive_scopes = sorted(granted - required)
    missing_scopes = sorted(required - granted)

    total_granted_risk = sum(
        risk_weights.get(scope, DEFAULT_RISK_WEIGHT)
        for scope in granted
    )

    excessive_risk = sum(
        risk_weights.get(scope, DEFAULT_RISK_WEIGHT)
        for scope in excessive_scopes
    )

    exposure_score = (
        round((excessive_risk / total_granted_risk) * 100, 2)
        if total_granted_risk > 0
        else 0.0
    )

    return {
        "matched_scopes": matched_scopes,
        "excessive_scopes": excessive_scopes,
        "missing_scopes": missing_scopes,
        "exposure_score": exposure_score,
    }
