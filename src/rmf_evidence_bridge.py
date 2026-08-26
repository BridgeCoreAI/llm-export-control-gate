"""
RMF Evidence Bridge.

Transforms the LLM Export-Control Gate's hash-chained audit trail into
evidence records compatible with the GSEL for RMF, ATO Accelerator's
evidence log (gsel_rmf.evidence), so a system that includes this gate
can cite its live enforcement decisions as evidence for the relevant
NIST SP 800-53 controls during the Assess step, and have that evidence
watched by the Accelerator's Monitor drift detection.

IMPORTANT: this module targets the RMF ATO Accelerator's DOCUMENTED
interface (see https://github.com/BridgeCoreAI/rmf-ato-accelerator).
Verify field names against the actual gsel_rmf.evidence module before
merging this bridge into a production integration. If the schema
differs, only the `to_rmf_evidence_record` function in this file needs
adjustment; nothing else in the Gate depends on this bridge.
"""

from dataclasses import dataclass, asdict, field
from typing import List

from .audit_trail import LogEntry, AuditTrail


# Which of the Gate's control mappings correspond to which RMF control
# family, for the purpose of grouping evidence by the control it
# supports. This is a reference mapping; adjust to match your actual
# selected baseline for a given system.
GATE_TO_RMF_CONTROL_FAMILY = {
    "NIST-800-171-3.1.3": "AC-4",   # Information Flow Enforcement
    "CMMC-L3-AC.L2-3.1.3": "AC-4",
    "NIST-800-171-3.13.1": "SC-7",  # Boundary Protection
    "CMMC-L3-SC.L2-3.13.1": "SC-7",
    "NIST-800-171-3.6.1": "IR-6",   # Incident Reporting (flagged items)
    "CMMC-L3-IR.L2-3.6.1": "IR-6",
}


@dataclass
class RMFEvidenceRecord:
    """
    One evidence record in the format the RMF ATO Accelerator's
    evidence log is documented to expect: an entry tied to a specific
    control, carrying a hash for tamper-evidence, and a human-readable
    description an assessor can read without needing to understand the
    Gate's internal decision codes.
    """
    control_id: str
    source_system: str
    evidence_type: str          # "runtime_enforcement_log"
    timestamp: str
    description: str
    source_hash: str            # the Gate's own entry_hash, carried through unmodified
    source_sequence: int
    raw_decision: str
    raw_reason_code: str
    reviewer_identity: str = None


def _describe(entry: LogEntry) -> str:
    if entry.reviewer_identity:
        return (
            f"Human-reviewed decision: {entry.decision} for a {entry.data_class} "
            f"request destined for {entry.destination}. Reason: {entry.reason_code}. "
            f"Reviewed by {entry.reviewer_identity}."
        )
    return (
        f"Automated gate decision: {entry.decision} for a {entry.data_class} "
        f"request destined for {entry.destination}. Reason: {entry.reason_code}."
    )


def to_rmf_evidence_record(entry: LogEntry, source_system: str) -> List[RMFEvidenceRecord]:
    """
    Convert a single Gate LogEntry into one or more RMFEvidenceRecord
    objects, one per RMF control family the entry provides evidence
    for. A single decision can support multiple controls (for example,
    a BLOCKED decision supports both AC-4 and SC-7), so this returns a
    list, not a single record.
    """
    records = []
    seen_families = set()
    for gate_control, rmf_family in GATE_TO_RMF_CONTROL_FAMILY.items():
        if gate_control in entry.control_mapping and rmf_family not in seen_families:
            seen_families.add(rmf_family)
            records.append(RMFEvidenceRecord(
                control_id=rmf_family,
                source_system=source_system,
                evidence_type="runtime_enforcement_log",
                timestamp=entry.timestamp,
                description=_describe(entry),
                source_hash=entry.entry_hash,
                source_sequence=entry.sequence,
                raw_decision=entry.decision,
                raw_reason_code=entry.reason_code,
                reviewer_identity=entry.reviewer_identity,
            ))
    return records


def bridge_audit_trail(trail: AuditTrail, source_system: str) -> List[RMFEvidenceRecord]:
    """
    Convert an entire AuditTrail into a flat list of RMFEvidenceRecord
    objects, in original sequence order, ready to be appended to an
    RMF Accelerator evidence log for the Assess step.

    Per the Accelerator's Monitor design (continuous evidence freshness
    and chain integrity checking, returning to Assess on drift), this
    function does NOT re-verify the Gate's chain itself; call
    trail.verify_chain() separately before bridging, and refuse to
    bridge evidence from a trail that fails verification. Bridging
    evidence from a tampered trail would silently launder a compromised
    audit log into the RMF evidence store, which is exactly the failure
    this bridge exists to prevent, not enable.
    """
    if not trail.verify_chain():
        raise ValueError(
            "Refusing to bridge evidence from an audit trail that fails "
            "chain verification. The source trail must be verified intact "
            "before its entries can be trusted as RMF evidence."
        )

    records = []
    for entry in trail.entries():
        records.extend(to_rmf_evidence_record(entry, source_system))
    return records


def detect_new_evidence_since(trail: AuditTrail, last_bridged_sequence: int) -> List[LogEntry]:
    """
    Support for the Accelerator's continuous Monitor step: given the
    sequence number of the last entry already bridged into the RMF
    evidence log, return only the entries added since then. This lets
    Monitor pull incremental evidence on a schedule rather than
    re-bridging the entire trail every cycle.
    """
    return [e for e in trail.entries() if e.sequence > last_bridged_sequence]
