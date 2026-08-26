"""
Classification module for the LLM Export-Control Gate.

Reference implementation only. This is a rule-based, explainable
classifier using pattern and keyword matching. It is NOT a substitute
for an organization's actual export-control or CUI classification
authority. See docs/SPECIFICATION.md Section 6 and Section 8.
"""

from dataclasses import dataclass, field
from enum import Enum
import re


class DataClass(str, Enum):
    PUBLIC = "PUBLIC"
    CUI = "CUI"
    ITAR_CONTROLLED = "ITAR-CONTROLLED"
    UNRECOGNIZED = "UNRECOGNIZED"  # classification failure, must fail closed


@dataclass
class ClassificationResult:
    data_class: DataClass
    matched_rules: list = field(default_factory=list)


# Reference rule sets. Organizations MUST replace these with their own
# classification authority's determinations before any production use.
# These patterns are illustrative examples only, not a complete or
# authoritative ITAR/CUI keyword list.

ITAR_PATTERNS = [
    r"\bITAR\b",
    r"\bexport[- ]controlled\b",
    r"\bUSML\b",
    r"\bmunitions list\b",
    r"\bdefense article\b",
    r"\btechnical data package\b",
    r"\bDDTC\b",
]

CUI_PATTERNS = [
    r"\bCUI\b",
    r"\bcontrolled unclassified\b",
    r"\bFOUO\b",
    r"\bfor official use only\b",
    r"\bNOFORN\b",
]


def _matches(text: str, patterns: list) -> list:
    hits = []
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            hits.append(pattern)
    return hits


def classify(request_text: str, context_text: str = "") -> ClassificationResult:
    """
    Classify a request and its attached context.

    Per specification Section 6, this checks the highest-sensitivity
    class first. ITAR markers take precedence over CUI markers if both
    are present, since ITAR-controlled data carries the stricter
    handling requirement. Fail-closed: if input is malformed (None,
    non-string), the result is UNRECOGNIZED, which the gate must
    always resolve to Blocked (guarantee G2).
    """
    if request_text is None or not isinstance(request_text, str):
        return ClassificationResult(data_class=DataClass.UNRECOGNIZED, matched_rules=["malformed_input"])

    combined = f"{request_text}\n{context_text or ''}"

    itar_hits = _matches(combined, ITAR_PATTERNS)
    if itar_hits:
        return ClassificationResult(data_class=DataClass.ITAR_CONTROLLED, matched_rules=itar_hits)

    cui_hits = _matches(combined, CUI_PATTERNS)
    if cui_hits:
        return ClassificationResult(data_class=DataClass.CUI, matched_rules=cui_hits)

    return ClassificationResult(data_class=DataClass.PUBLIC, matched_rules=[])
