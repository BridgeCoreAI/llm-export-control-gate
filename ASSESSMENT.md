
# AI Security & Privacy Capability Self-Appraisal

LLM Export-Control Gate · CMMI V2.0-Informed Practice Achievement Appraisal

Report ID: BC-ASP-001 · Version 1.0 (Verified by owner, 2026-10-25)
Owner and appraiser: Grace M. Adjeli, BridgeCore AI · Date: 2026-10-25
Classification: Public · Validity: 12 months from verification date

## 1. Appraisal Charter

Sponsor: Grace M. Adjeli. Scope: the LLM Export-Control Gate reference
implementation: classification aware request admissibility (PUBLIC, CUI,
ITAR), prompt injection and exfiltration screening, permit, block, and
review outcomes, and tamper evident evidence bridging to NIST SP 800-53
control mappings.

Method: self appraisal informed by CMMI V2.0 practice achievement
ratings and the SCAMPI evidence model. Three evidence types are used:
artifacts (documents and code), affirmations (attested statements), and
demonstrations (observed live runs). Practice ratings: Fully Achieved,
Largely Achieved, Partially Achieved, Not Achieved. Practice area
capability levels: 0 Incomplete, 1 Initial, 2 Managed, 3 Defined.

Calibrated claim: this is a self appraisal by the owner of the work. It
is not a benchmark appraisal and no CMMI maturity level certification is
claimed. Independent validation is invited and its absence is recorded
as a limitation (Section 7).

## 2. Practice Areas, Practices, and Proposed Ratings

Ratings were proposed in draft 0.9 and confirmed by the owner on
2026-10-25 without correction. Revisions, if any, are logged in Section 8.

PA-01 Threat and Adversarial Risk Management (proposed capability level 2)
- P1.1 AI specific threats are identified and catalogued. PROPOSED:
  Fully Achieved. Evidence: direct injection, injection in context,
  jailbreak, malformed input, and exfiltration cases exist as executable
  tests (E-01).
- P1.2 Threats are screened at the enforcement point before model
  access. PROPOSED: Fully Achieved. Evidence: gate screens requests
  before endpoint admissibility (E-03, E-04).
- P1.3 Threat knowledge is reviewed on a defined cycle. PROPOSED:
  Partially Achieved. Gap: mapping to OWASP LLM Top 10 is asserted but
  no dated review cycle exists (E-03).

PA-02 Data Classification and Privacy Protection (proposed level 2)
- P2.1 Data classes are defined with precedence rules. PROPOSED: Fully
  Achieved. Evidence: PUBLIC, CUI, ITAR classes; ITAR precedence over
  CUI when both present (E-01).
- P2.2 Classification evaluates request context, not only the request
  text. PROPOSED: Fully Achieved. Evidence: dedicated tests for context
  based classification and case insensitive matching (E-01).
- P2.3 Data minimization and retention posture is documented.
  PROPOSED: Partially Achieved. Gap: zero retention intent is stated in
  narrative form; no retention policy document exists (E-03).

PA-03 Enforcement Decision Logic (proposed level 2)
- P3.1 Every request receives an explicit decision outcome. PROPOSED:
  Fully Achieved. Evidence: permit, block, and review outcomes are
  implemented and tested (E-01, E-04).
- P3.2 Flagged requests carry the matched detection detail. PROPOSED:
  Fully Achieved. Evidence: flagged results include matched patterns
  (E-01).
- P3.3 A human review path exists for borderline cases. PROPOSED: Fully
  Achieved. Evidence: review outcome class and reviewer identity carried
  into evidence (E-02).

PA-04 Evidence and Traceability (proposed level 2)
- P4.1 Decision events produce evidence records. PROPOSED: Fully
  Achieved. Evidence: bridged evidence records with hashes and sequence
  numbers (E-02).
- P4.2 Evidence integrity resists tampering. PROPOSED: Fully Achieved.
  Evidence: tampered chains, deleted entries, and unverified trails are
  refused (E-02).
- P4.3 Evidence is independently verifiable by a stranger. PROPOSED:
  Fully Achieved. Evidence: tests run in public CI on every change;
  results are reproducible by cloning and running the suite (E-01, E-06).

PA-05 Verification and Validation (proposed level 2)
- P5.1 An executable test suite covers the claims. PROPOSED: Fully
  Achieved. Evidence: 55 tests (33 gate, 22 evidence bridge), all
  passing in public CI (E-01, E-02, E-06).
- P5.2 Adversarial cases are included, not only happy paths. PROPOSED:
  Fully Achieved. Evidence: injection, jailbreak, malformed input, and
  tamper attempts in the suite (E-01, E-02).
- P5.3 Tests execute automatically on every change. PROPOSED: Fully
  Achieved. Evidence: CI workflow runs on push and pull request (E-06).
- P5.4 Published claims match executable checks. PROPOSED: Fully
  Achieved. Evidence: README test count equals CI result (E-03, E-06).

PA-06 Governance and Oversight (proposed level 2)
- P6.1 A named accountable owner exists. PROPOSED: Fully Achieved.
  Evidence: author and owner named in repository documentation (E-03).
- P6.2 Scope and limitations are declared. PROPOSED: Fully Achieved.
  Evidence: README states reference implementation status and that no
  certification of export control compliance is claimed (E-03).
- P6.3 A review cadence for the appraisal itself is defined. PROPOSED:
  Partially Achieved. Gap: no annual re appraisal rule documented
  before this report (this report establishes it, Section 8).

## 3. Evidence Register

| ID | Type | Artifact | Location |
|----|------|----------|----------|
| E-01 | Artifact | Gate test suite (33 tests) | tests/test_gate.py |
| E-02 | Artifact | Evidence bridge test suite (22 tests) | tests/test_rmf_evidence_bridge.py |
| E-03 | Artifact | README with claims, scope, limitations | README.md |
| E-04 | Demonstration | Full adversarial and conformance suite run, 55 tests | Appendix A output |
| E-05 | Affirmation | Owner attestation and conflicts statement | Appendix B |
| E-06 | Artifact | Public CI run records | GitHub Actions |

## 4. Findings

Strengths
- Adversarial evidence is executable and public (E-01, E-04): claims
  about injection and exfiltration defense can be rerun by anyone.
- Evidence integrity is tested against attack, not assumed (E-02).
- Claims are calibrated: the repository declares what it is and what it
  is not (E-03).

Weaknesses
- W1: no dated threat model review cycle (P1.3).
- W2: retention and minimization posture undocumented (P2.3).
- W3: appraisal re-run cadence established only now (P6.3).

Opportunities for improvement
- OFI-1: invite independent verification; publish the result either way.
- OFI-2: attach the recorded demonstration to the README.
- OFI-3: date and schedule the annual threat model refresh.

## 5. Action Plan

| ID | Action | Owner | Evidence of closure |
|----|--------|-------|---------------------|
| A-01 | Date and schedule annual threat model review against OWASP LLM Top 10 | Grace Adjeli | Review note committed to repo |
| A-02 | Write and commit data retention and minimization statement | Grace Adjeli | Document in repo |
| A-03 | Record demonstration D-01 and link output in README | Grace Adjeli | Appendix A completed and linked |
| A-04 | Invite independent verification and publish the response | Grace Adjeli | Linked result, either verdict |
| A-05 | Add next appraisal date to this report on verification | Grace Adjeli | Section 8 entry |

## 6. Capability Summary

Six practice areas are assessed at capability level 2 (Managed):
practices are planned, performed, and evidenced at the project level,
but not yet standardized across a wider organizational unit, and not
independently validated. No claim is made regarding levels 3 to 5.

## 7. Method Notes and Limitations

Single appraiser with an ownership interest in the work product. No
appraisal team, no sampling plan, no benchmark method. Demonstration
evidence is captured once and may not represent all conditions. Ratings
are judgments against the cited evidence and are revisable by the owner;
this report does not constitute certification, legal advice, or export
control compliance assurance.

## 8. Revision Log

| Version | Date | Change | Author |
|---------|------|--------|--------|
| 1.0 | 2026-10-25 | Appendix A completed; sequencing gap (attestation before evidence) identified in review and corrected | Grace Adjeli |

## Appendix A: Demonstration D-01 (record and paste output)

Run in a local clone of this repository:

1. python3 -m pytest tests/ -q
   Expected: 55 passed.

Recorded output: 55 passed in 0.11s

## Appendix B: Owner Attestation

I attest that the evidence register is accurate, that the demonstration
output in Appendix A is genuine, and that I have an ownership interest
in this work product. I have reviewed every proposed rating in Section 2
and confirm or correct it below.

Signed: Grace M. Adjeli · Date: 2026-10-25
Rating corrections, if any: none. All proposed ratings in Section 2 are confirmed after review against the cited evidence.
