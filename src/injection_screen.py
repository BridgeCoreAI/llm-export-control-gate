"""
Prompt injection and extraction screening.

Reference implementation only. Pattern-based screening for common
injection and extraction attempt signatures. This is a defensible
starting point, not a complete defense against a determined adversary.
Organizations should extend this with their own threat intelligence.
"""

import re

INJECTION_PATTERNS = [
    r"ignore (all )?(previous|prior|above) instructions",
    r"disregard (all )?(previous|prior|above)",
    r"you are now",
    r"act as (an? )?(unrestricted|jailbroken|dan)\b",
    r"reveal your (system prompt|instructions)",
    r"repeat (the )?(text|words) above",
    r"what (were|are) you told (before|prior)",
    r"bypass (your )?(safety|content) (filter|policy)",
]


def screen_for_injection(request_text: str, context_text: str = "") -> list:
    """
    Returns a list of matched injection/extraction patterns, if any.
    An empty list means no suspected injection detected. This does not
    itself decide the outcome; the gate decides how to weigh a
    detected pattern (see gate.py).

    The attached context is screened together with the request text,
    mirroring classification.py: an injection attempt smuggled in via
    context while the request text looks clean must still be caught.
    """
    if request_text is None or not isinstance(request_text, str):
        return ["malformed_input"]

    combined = f"{request_text}\n{context_text or ''}"

    hits = []
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            hits.append(pattern)
    return hits
