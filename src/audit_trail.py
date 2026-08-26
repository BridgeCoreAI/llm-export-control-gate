"""
Tamper-evident audit trail.

Every decision is logged as an entry hash-chained to the previous
entry, per specification Section 5, Guarantee G4. Altering any past
entry invalidates the chain from that point forward, which is how a
verifier detects tampering without needing a trusted third party.
"""

from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
import hashlib
import json


GENESIS_HASH = "0" * 64


@dataclass
class LogEntry:
    sequence: int
    timestamp: str
    decision: str            # PERMITTED | BLOCKED | FLAGGED | OVERRIDE_PERMIT | OVERRIDE_BLOCK
    data_class: str
    destination: str
    reason_code: str
    control_mapping: list
    reviewer_identity: str = None   # populated only for human overrides
    previous_hash: str = GENESIS_HASH
    entry_hash: str = field(init=False, default="")

    def compute_hash(self) -> str:
        payload = {
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "decision": self.decision,
            "data_class": self.data_class,
            "destination": self.destination,
            "reason_code": self.reason_code,
            "control_mapping": self.control_mapping,
            "reviewer_identity": self.reviewer_identity,
            "previous_hash": self.previous_hash,
        }
        serialized = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


class AuditTrail:
    def __init__(self):
        self._entries: list[LogEntry] = []

    def append(self, decision: str, data_class: str, destination: str,
               reason_code: str, control_mapping: list,
               reviewer_identity: str = None) -> LogEntry:
        if not control_mapping:
            # Guarantee G5: no decision without a control mapping.
            raise ValueError(
                f"Refusing to log decision '{decision}' with no control mapping. "
                "Every decision must map to at least one named control."
            )

        previous_hash = self._entries[-1].entry_hash if self._entries else GENESIS_HASH
        entry = LogEntry(
            sequence=len(self._entries),
            timestamp=datetime.now(timezone.utc).isoformat(),
            decision=decision,
            data_class=data_class,
            destination=destination,
            reason_code=reason_code,
            control_mapping=control_mapping,
            reviewer_identity=reviewer_identity,
            previous_hash=previous_hash,
        )
        entry.entry_hash = entry.compute_hash()
        self._entries.append(entry)
        return entry

    def entries(self) -> list:
        return list(self._entries)

    def verify_chain(self) -> bool:
        """
        Returns True if every entry's stored hash matches a freshly
        recomputed hash, AND every entry's previous_hash correctly
        links to the prior entry. Returns False the moment either
        check fails, meaning tampering is detected from that point
        forward, per guarantee G4.
        """
        expected_previous = GENESIS_HASH
        for entry in self._entries:
            if entry.previous_hash != expected_previous:
                return False
            recomputed = entry.compute_hash()
            if recomputed != entry.entry_hash:
                return False
            expected_previous = entry.entry_hash
        return True
