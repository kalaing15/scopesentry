from typing import List, Tuple


INTENT_SCOPE_MAP = {
    "read_files": ["drive.readonly"],
    "upload_files": ["drive.file"],
    "read_email": ["gmail.readonly"],
    "send_email": ["gmail.send"],
    "view_calendar": ["calendar.readonly"],
    "manage_calendar": ["calendar.events"],
    "read_contacts": ["contacts.readonly"],
    "read_profile": ["userinfo.profile"],
}


def normalize_intent(intent: str) -> str:
    """Convert user-friendly intent text into a standard format."""
    return intent.strip().lower().replace("-", "_").replace(" ", "_")


def map_intents_to_scopes(
    intended_actions: List[str],
) -> Tuple[List[str], List[str]]:
    """
    Return the minimum required scopes and any unsupported intentions.
    """
    required_scopes = set()
    unknown_intents = []

    for action in intended_actions:
        normalized_action = normalize_intent(action)
        mapped_scopes = INTENT_SCOPE_MAP.get(normalized_action)

        if mapped_scopes is None:
            unknown_intents.append(action)
        else:
            required_scopes.update(mapped_scopes)

    return sorted(required_scopes), unknown_intents