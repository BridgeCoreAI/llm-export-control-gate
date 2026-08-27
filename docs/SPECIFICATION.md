# LLM Export-Control Gate: Formal Specification v1.0

**BridgeCore AI, Governance Systems Engineering Lab (GSEL)**

*Governance is not what is defined. It is what is enforced at execution.*

---

## 1. Purpose

This specification defines a runtime admissibility gate that sits between an enterprise request stream and any LLM endpoint, enforcing export-control and CUI handling requirements before a request reaches a model, not after.

The core guarantee: nothing controlled reaches an unapproved endpoint. Every decision is on record. Every record maps to a control.

This is a reference implementation. It demonstrates the enforcement architecture. It does not perform legally binding export-control classification. Real ITAR and CUI determinations require qualified legal and security review. The classification step in this system is a rule-based, explainable approximation intended to demonstrate the gate mechanism, not a substitute for an organization's actual classification authority.

## 2. Problem Statement

Organizations adopting LLMs inside environments that also handle ITAR-controlled technical data or CUI face a specific, concrete risk: a request containing controlled data can reach an unauthorized model endpoint before any human notices. A policy stating "do not paste ITAR data into a commercial model" is not enforcement. It is a hope.

This system replaces that hope with a checkpoint every request must pass through, with three defined outcomes, and a tamper-evident record of every decision made.

## 3. System Architecture

Four stages, executed in order for every request:

1. **Enterprise Request Stream.** Requests and their attached context arrive from mission software or enterprise users, destined for an LLM endpoint.
2. **Classification at Arrival.** Every request and its context is tagged before anything else happens: PUBLIC, CUI, or ITAR-CONTROLLED. Validity is resolved at arrival, not after the model answers.
3. **Admissibility Gate.** A policy checkpoint evaluates the tagged request against policy: which data classes may reach which model endpoints. The gate also screens prompts for injection and extraction attempts.
4. **Tamper-Evident Audit Trail.** Every decision (permit, block, flag, human override) is logged with a reason code and mapped to the specific control it satisfies.

## 4. The Three Outcomes

Every request that passes through the Admissibility Gate resolves to exactly one of three outcomes. There is no fourth outcome and no default-permit path.

### 4.1 Permitted

The request's classification is authorized for the destination endpoint. The request proceeds. The response returns to the requester. The decision is logged.

### 4.2 Blocked

The request's classification is not authorized for the destination endpoint (for example, ITAR-controlled data addressed to a commercial, non-enclave endpoint). The request is rejected with a reason code. It is never transmitted to the endpoint. The decision is logged.

### 4.3 Flagged

The request is ambiguous, or the gate detects a suspected prompt injection or extraction attempt. The request is held in a Human Review Queue for a named reviewer, subject to a defined timeout policy. If the timeout elapses without a human decision, the request defaults to Blocked, never to Permitted. The decision, and any subsequent human override, is logged.

## 5. Formal Guarantees

This system is designed to satisfy five guarantees, verified by the adversarial test suite described in Section 7.

**G1: Complete Mediation.** Every request that could reach an LLM endpoint passes through the Admissibility Gate. There is no path from the Enterprise Request Stream to a model endpoint that bypasses classification and gate evaluation.

**G2: Fail-Closed Default.** Any error, timeout, missing classification, or unrecognized data class results in Blocked, never Permitted. The absence of a decision is not an implicit permit.

**G3: No Silent Escalation to Permit.** A Flagged request can only become Permitted through an explicit, logged human decision. A Flagged request can never become Permitted through timeout, retry, or system default. The override must reference the specific flagged audit entry it resolves (by entry hash); an override cannot be logged against a request that was never flagged.

**G4: Immutable, Attributable Evidence.** Every decision produces a log entry containing the decision, the request's classification, the destination, a reason code, a timestamp, and (for human overrides) the identity of the reviewer. Log entries are hash-chained; altering a past entry invalidates the chain from that point forward.

**G5: Control Traceability.** Every logged decision maps to at least one named control (NIST SP 800-171 or CMMC Level 3 practice) that the decision satisfies. A decision with no control mapping is a defect.

## 6. Data Classification (Reference Implementation Scope)

The reference implementation classifies incoming requests using explainable pattern and keyword matching against a configurable rule set, not machine learning inference. This is a deliberate design choice: a classification decision that controls whether ITAR data reaches an external system must be explainable and auditable on its own terms, not inferred from an opaque model.

Three classes are recognized:

- **PUBLIC.** No control markers detected. Eligible for any approved endpoint.
- **CUI.** Contains markers consistent with Controlled Unclassified Information (configurable keyword and pattern rules, extensible per organization). Eligible only for endpoints explicitly approved for CUI handling.
- **ITAR-CONTROLLED.** Contains markers consistent with export-controlled technical data under the configured rule set. Eligible only for endpoints explicitly approved for ITAR-controlled data, which must also satisfy access-control requirements (for example, verified US-person status of the requester, outside the scope of this reference implementation).

Organizations deploying this pattern in production must replace or extend the reference rule set with their own classification authority's determinations. The gate architecture (Sections 3 through 5) is independent of the specific classification method used; classification is a pluggable input to the gate, not something the gate itself determines authoritatively.

## 7. Adversarial Test Categories

The reference implementation's test suite is organized around attempts to violate each guarantee in Section 5:

- Attempts to route a request to an endpoint without passing through classification (violates G1)
- Malformed, missing, or unrecognized classification input (must resolve to Blocked, verifying G2)
- Attempts to force a Flagged request to Permitted via timeout, retry, or repeated submission without human review (violates G3)
- Attempts to submit a request after tampering with a prior log entry, verifying the hash chain detects the tamper (violates G4)
- Any permit or block decision without a corresponding control mapping (violates G5)
- Prompt injection and extraction pattern attempts, verifying the gate flags rather than silently permits them

## 8. Explicit Non-Goals

This specification does not define or claim:

- Legally authoritative ITAR or CUI classification. That determination belongs to an organization's export-control and security compliance functions.
- User identity or access-control verification (for example, confirming a requester's US-person status for ITAR access). This system assumes that verification happens upstream or in a complementary system.
- Model output filtering. This gate controls what reaches a model, not what a model returns. Output-side controls are a separate concern.
- Durable storage. The reference implementation holds the audit trail in memory for demonstration purposes. A production deployment must persist entries to durable, access-controlled storage so the hash chain survives restarts and is protected from modification at rest.

---

*BridgeCore AI. bridgecore-ai.com*
*A reference architecture applying the Execution Governance Model's enforcement principles to export-controlled AI pipelines.*
