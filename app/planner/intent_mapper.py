from typing import List, Tuple

from app.providers.intent_catalog import (
    PROVIDER_INTENT_SCOPE_MAP,
    map_provider_intents,
    normalize_intent,
)


INTENT_SCOPE_MAP = {
    intent: list(scopes)
    for intent, scopes in PROVIDER_INTENT_SCOPE_MAP["google"].items()
}


def map_intents_to_scopes(
    intended_actions: List[str],
    provider: str = "google",
) -> Tuple[List[str], List[str]]:
    """
    Return the minimum required scopes and any unsupported intentions.
    """
    return map_provider_intents(provider, intended_actions)
