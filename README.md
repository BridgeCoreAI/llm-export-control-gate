# LLM Export-Control Gate

**BridgeCore AI, Governance Systems Engineering Lab (GSEL)**

*Governance is not what is defined. It is what is enforced at execution.*

A reference implementation of a runtime admissibility gate for AI pipelines that must handle ITAR-controlled technical data and CUI (Controlled Unclassified Information). It classifies every request at arrival, evaluates it against destination policy before it reaches a model, screens for prompt injection and extraction attempts, and produces a tamper-evident audit trail mapped to named NIST SP 800-171 and CMMC Level 3 controls.

The guarantee: nothing controlled reaches an unapproved endpoint. Every decision is on record. Every record maps to a control.

## Why this exists

Organizations adopting LLMs inside environments that also handle export-controlled or CUI data face a specific, concrete risk: a request containing controlled data can reach an unauthorized model endpoint before any human notices. A policy stating "do not paste ITAR data into a commercial model" is not enforcement. It is a hope.

Most AI governance guidance for these environments stops at the policy layer, telling people what they should not do, without a mechanism that actually stops them from doing it at the moment it matters. This project replaces that hope with a checkpoint every request must pass through, with three defined outcomes (permit, block, or flag for human review), and a tamper-evident record of every decision made.

It was built to demonstrate that principle for one specific, high-stakes case: AI systems operating inside defense and government environments where RMF, CMMC, and export control requirements already apply, and where an LLM is a new component that existing controls were not written with in mind.

## Important scope note

This is a reference architecture, not a legally binding classification system. The classification step uses explainable, rule-based pattern matching to demonstrate the gate mechanism. It does not replace an organization's actual export-control and CUI classification authority. See `docs/SPECIFICATION.md` Section 8 for explicit non-goals.

## Architecture

Four stages, every request in order:

1. **Enterprise Request Stream.** Requests and context arrive from mission software or enterprise users.
2. **Classification at Arrival.** Every request is tagged PUBLIC, CUI, or ITAR-CONTROLLED before anything else happens.
3. **Admissibility Gate.** A policy checkpoint evaluates the tagged request against which data classes may reach which endpoints, and screens for injection and extraction attempts.
4. **Tamper-Evident Audit Trail.** Every decision (permit, block, flag, human override) is logged with a reason code, hash-chained to the previous entry, and mapped to a named control.

Every request resolves to exactly one of three outcomes: **Permitted**, **Blocked**, or **Flagged** for human review. There is no fourth outcome and no default-permit path.

## Formal guarantees

Five guarantees, each backed by a dedicated adversarial test category:

- **G1, Complete Mediation.** No path from request to model bypasses the gate.
- **G2, Fail-Closed Default.** Errors, timeouts, and unrecognized input resolve to Blocked, never Permitted.
- **G3, No Silent Escalation to Permit.** A Flagged request becomes Permitted only through an explicit, logged human decision. Never through timeout or retry.
- **G4, Immutable, Attributable Evidence.** Every decision is hash-chained. Tampering with any past entry is detectable.
- **G5, Control Traceability.** Every decision maps to at least one named control. A decision with no control mapping is rejected.

Full specification: `docs/SPECIFICATION.md`

## Running it

```bash
pip install pytest
python3 demo.py          # runnable end-to-end demonstration
python3 -m pytest tests/ -v    # full adversarial and conformance test suite
```

Current status: **55 adversarial and conformance tests passing.**

## Project structure

```
llm-export-control-gate/
  docs/
    SPECIFICATION.md      (formal specification, guarantees, non-goals)
  src/
    classification.py     (rule-based data classification)
    injection_screen.py   (prompt injection/extraction screening)
    audit_trail.py         (hash-chained tamper-evident logging)
    gate.py                 (the Admissibility Gate itself)
    rmf_evidence_bridge.py   (bridges audit trail into RMF Accelerator evidence)
  tests/
    test_gate.py            (adversarial tests, organized by guarantee)
    test_rmf_evidence_bridge.py  (adversarial tests for the RMF bridge)
  demo.py                    (runnable end-to-end demonstration)
```

## Relationship to other BridgeCore AI work

This applies the same enforcement-at-execution principles verified in the [Execution Governance Model](https://github.com/GraceAdjeliGRCAI/execution-governance-model) to a specific, high-stakes pipeline shape: AI systems operating inside environments that also handle export-controlled and CUI data. It follows the same GSEL four-pillar discipline (Engineer, Enforce, Verify, Sustain) applied in the [GSEL for RMF, ATO Accelerator](https://github.com/BridgeCoreAI/rmf-ato-accelerator).

### RMF Evidence Bridge

`src/rmf_evidence_bridge.py` connects this Gate's live audit trail directly to the RMF Accelerator's evidence pipeline. Instead of an AI-drafted paragraph describing how an Information Flow Enforcement control is implemented, a system that includes this Gate can cite real, hash-chained enforcement decisions as its Assess-step evidence for NIST SP 800-53 controls AC-4 (Information Flow Enforcement), SC-7 (Boundary Protection), and IR-6 (Incident Reporting, for flagged items).

The bridge refuses to hand off evidence from any audit trail that fails its own tamper-check, on principle: bridging evidence from a compromised log would launder a broken guarantee into an authorization package, which is precisely the failure this integration exists to prevent. See `tests/test_rmf_evidence_bridge.py` for the adversarial tests covering this behavior, including tampering, entry deletion, and reordering attempts.

`detect_new_evidence_since()` supports the Accelerator's continuous Monitor step, allowing incremental evidence pulls rather than reprocessing the full trail on every monitoring cycle.

**Note:** this bridge targets the RMF ATO Accelerator's documented interface. Verify field names against the actual `gsel_rmf.evidence` module before relying on this integration in a real authorization effort.

---

*BridgeCore AI. bridgecore-ai.com*
