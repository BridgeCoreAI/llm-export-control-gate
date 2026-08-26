"""
The Admissibility Gate.

This is the enforcement checkpoint described in specification Section
3, Stage 3. Every request must pass through evaluate() before any
response is returned. There is no path to PERMITTED that bypasses
this function.
"""

from dataclasses import dataclass
from enum import Enum
from datetime import datetime, timezone

from .classification import classify, DataClass, ClassificationResult
from .injection_screen import screen_for_injection
from .audit_trail import AuditTrail


class Decision(str, Enum):
    PERMITTED = "PERMITTED"
    BLOCKED = "BLOCKED"
    FLAGGED = "FLAGGED"


# Control mapping: which named controls does each decision type satisfy.
# Reference mappings only; adapt to your organization's actual control
# implementation statements.
CONTROL_MAP = {
    Decision.PERMITTED: ["NIST-800-171-3.1.3", "CMMC-L3-AC.L2-3.1.3"],
    Decision.BLOCKED: ["NIST-800-171-3.1.3", "NIST-800-171-3.13.1", "CMMC-L3-SC.L2-3.13.1"],
    Decision.FLAGGED: ["NIST-800-171-3.6.1", "CMMC-L3-IR.L2-3.6.1"],
}

# Policy: which data classes are authorized for which destination
# endpoints. Reference policy only; configure per your organization's
# actual approved enclaves.
DEFAULT_POLICY = {
    "commercial-llm-endpoint": {DataClass.PUBLIC},
    "cui-approved-enclave": {DataClass.PUBLIC, DataClass.CUI},
    "itar-approved-enclave": {DataClass.PUBLIC, DataClass.CUI, DataClass.ITAR_CONTROLLED},
}


@dataclass
class GateResult:
    decision: Decision
    data_class: DataClass
    reason_code: str
    injection_flags: list
    log_entry_hash: str


class AdmissibilityGate:
    def __init__(self, audit_trail: AuditTrail, policy: dict = None):
        self.audit_trail = audit_trail
        self.policy = policy if policy is not None else DEFAULT_POLICY

    def evaluate(self, request_text: str, destination: str, context_text: str = "") -> GateResult:
        """
        Evaluate a single request. This is the only path by which a
        request may be marked PERMITTED. Guarantee G1 (Complete
        Mediation): calling code must route every request through
        this method before it reaches an LLM endpoint. There is no
        other sanctioned path.
        """
        classification = classify(request_text, context_text)
        injection_flags = screen_for_injection(request_text)

        # Guarantee G2: fail closed on unrecognized classification.
        if classification.data_class == DataClass.UNRECOGNIZED:
            return self._log_and_return(
                Decision.BLOCKED, classification.data_class, destination,
                reason_code="UNRECOGNIZED_CLASSIFICATION_FAIL_CLOSED",
            )

        # Suspected injection/extraction attempt: flag, never silently permit.
        if injection_flags:
            return self._log_and_return(
                Decision.FLAGGED, classification.data_class, destination,
                reason_code="SUSPECTED_INJECTION_OR_EXTRACTION",
            )

        # Unknown destination is treated the same as an unauthorized
        # destination: fail closed, never fail open.
        authorized_classes = self.policy.get(destination, set())

        if classification.data_class in authorized_classes:
            return self._log_and_return(
                Decision.PERMITTED, classification.data_class, destination,
                reason_code="CLASSIFICATION_AUTHORIZED_FOR_DESTINATION",
            )

        return self._log_and_return(
            Decision.BLOCKED, classification.data_class, destination,
            reason_code="CLASSIFICATION_NOT_AUTHORIZED_FOR_DESTINATION",
        )

    def resolve_flagged(self, destination: str, data_class: DataClass,
                         reviewer_identity: str, human_decision: str,
                         reason_code: str) -> GateResult:
        """
        The ONLY path by which a FLAGGED request may become PERMITTED.
        Guarantee G3: this requires an explicit reviewer_identity. A
        FLAGGED request can never become PERMITTED through timeout,
        retry, or any path other than this explicit human decision.
        """
        if not reviewer_identity:
            raise ValueError(
                "resolve_flagged requires a reviewer_identity. "
                "A flagged request cannot be resolved without an accountable human."
            )
        if human_decision not in (Decision.PERMITTED, Decision.BLOCKED):
            raise ValueError("human_decision must be PERMITTED or BLOCKED.")

        decision = human_decision
        log_decision = "OVERRIDE_PERMIT" if decision == Decision.PERMITTED else "OVERRIDE_BLOCK"
        entry = self.audit_trail.append(
            decision=log_decision,
            data_class=data_class,
            destination=destination,
            reason_code=reason_code,
            control_mapping=CONTROL_MAP[decision],
            reviewer_identity=reviewer_identity,
        )
        return GateResult(
            decision=decision, data_class=data_class, reason_code=reason_code,
            injection_flags=[], log_entry_hash=entry.entry_hash,
        )

    def resolve_timeout(self, destination: str, data_class: DataClass, reason_code: str) -> GateResult:
        """
        A FLAGGED request whose human review timeout has elapsed.
        Guarantee G3: timeout resolves to BLOCKED, never PERMITTED.
        """
        return self._log_and_return(
            Decision.BLOCKED, data_class, destination,
            reason_code=f"REVIEW_TIMEOUT_FAIL_CLOSED:{reason_code}",
        )

    def _log_and_return(self, decision: Decision, data_class: DataClass,
                         destination: str, reason_code: str) -> GateResult:
        entry = self.audit_trail.append(
            decision=decision.value,
            data_class=data_class.value,
            destination=destination,
            reason_code=reason_code,
            control_mapping=CONTROL_MAP[decision],
        )
        return GateResult(
            decision=decision, data_class=data_class, reason_code=reason_code,
            injection_flags=[], log_entry_hash=entry.entry_hash,
        )
