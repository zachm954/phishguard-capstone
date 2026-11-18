# PhishGuard — Capstone 2 QA Gap Analysis

**Date:** November 2, 2026  
**Repository:** `zachm954/phishguard-capstone`  
**Branch reviewed:** `main`  
**Prepared for:** PhishGuard QA / Capstone 2  
**Assessment type:** Documentation and static code review; **not** a live application test or independent reproduction of prior test results.

## 1. Purpose and scope

Identify discrepancies between the PhishGuard website prototype, documented requirements, previous sprint testing, and security controls. Prioritize the remaining QA work needed for a demonstrable, trustworthy website. The Chrome extension is **out of scope** for this assessment per the team's current direction, although the README still describes it as a stretch goal.

**Reviewed evidence**

- `README.md`
- `docs/Requirements/User_Stories.md`
- `docs/Requirements/Acceptance_Criteria.md`
- `docs/Testing/Sprint_1/README.md`
- `docs/Testing/Sprint_2_US7_Testing/README.md`
- `docs/Testing/Sprint_3_US10_Testing/README.md`
- `docs/Testing/Sprint_4_US16_Testing/README.md`
- `docs/DATA_PROTECTION.md`
- `docs/THREATS.md`
- `prototype/App.tsx` (reviewed relevant analysis, validation, storage, and UI sections)

Other documents and image attachments exist in the repository but were not all examined in detail. Findings below therefore describe the **reviewed evidence**, not a claim that no other evidence exists anywhere in the project.

## 2. Executive summary

The project has documented test execution across multiple sprints and a working implementation of URL-scoring logic in the inspected prototype source. However, the reviewed material shows an important **privacy-control conflict**, **requirements/implementation inconsistencies**, and **unverified release-security and detection-accuracy claims**. The current known-bad list is explicitly demonstration-only. A passing heuristic regression test is not equivalent to proven phishing-detection accuracy.

**Reported sprint outcomes (not independently rerun):**

| Evidence | Reported outcome | Interpretation |
|---|---|---|
| Sprint 2 US7 | 5/5 PASS | Earlier scoring implementation |
| Sprint 3 US10 | 5/5 regression cases matched revised scoring | Updated heuristic implementation |
| Sprint 4 US16 | 8/8 supplemental cases PASS | Separate suite; not an overall QA pass rate |
| Sprint 1 README | Empty | No test execution information in this file |
| Security verification log | V1–V10 result cells blank | No execution evidence recorded in that log |

## 3. Findings and recommended actions

### GAP-01 — Sensitive scan URLs persisted in browser storage

**Priority:** High  
**Type:** Code/documentation conflict; security/privacy  
**Evidence:** `prototype/App.tsx` reads `localStorage.getItem("phishfinder_history")` and saves submitted URLs with `localStorage.setItem("phishfinder_history", JSON.stringify(updatedHistory))`. `docs/DATA_PROTECTION.md` (D1, D2, ASVS 8.2.2) and `docs/THREATS.md` state that submitted URLs and scan results should not be stored persistently.

**Risk:** A submitted URL can contain tokens, credentials, or sensitive query parameters. Browser persistence contradicts the current stated data-handling policy.

**Recommended action:** Agree whether history is required. Preferred privacy-preserving MVP option: remove persistent URL history and clear any previously saved history key, or redesign history with documented consent, retention, redaction, and security safeguards. Do not silently relax the requirement.

**Verification / exit criterion:** A scan using `https://example.com/?token=qa-placeholder` leaves no submitted URL or token in local/session storage, cookies, application URL, or logs; the chosen history policy is reflected in requirements and UI.

### GAP-02 — Real-world phishing-detection accuracy is unmeasured

**Priority:** High  
**Type:** Test coverage / product assurance  
**Evidence:** Sprint 2–4 reports test selected URLs against expected heuristic outcomes. No labeled, representative benign-versus-phishing evaluation with confusion-matrix metrics was established in the reviewed evidence.

**Risk:** A system can pass expected-score tests while still missing phishing links or incorrectly flagging legitimate links.

**Recommended action:** Define a reproducible, safely handled evaluation dataset with benign and defanged/labeled phishing samples. Record ground truth, predicted verdict, score, and triggered indicators. Calculate true positives, false positives, true negatives, false negatives, precision, recall, and false-positive rate. Agree acceptance thresholds with the team before release. Do not open live malicious URLs to run these tests.

**Verification / exit criterion:** A versioned evaluation report documents dataset provenance, sample counts, class balance, confusion matrix, metrics, limitations, and agreed pass/fail thresholds.

### GAP-03 — Known-bad detection uses demonstration entries

**Priority:** High for production claims; Medium for an explicitly labeled classroom demonstration  
**Type:** Functional limitation / release communication  
**Evidence:** `prototype/App.tsx` contains `KNOWN_BAD_DOMAINS = new Set(["malicious.example.test"])` and a corresponding demonstration URL. Sprint 3 and 4 reports explicitly identify the local list as demonstration-only.

**Risk:** Viewers could infer real-time or broad threat-intelligence coverage that does not exist.

**Recommended action:** Either integrate and test a maintained intelligence source, with safe update/error handling, or label known-bad matching clearly as a demonstration and avoid claims of production-grade coverage.

**Verification / exit criterion:** Demo and README accurately describe the source and coverage; known-bad regression tests pass; any integrated feed has documented freshness, failure handling, and safe matching.

### GAP-04 — Risk-tier acceptance criteria do not match implementation

**Priority:** Medium  
**Type:** Requirements traceability  
**Evidence:** `docs/Requirements/Acceptance_Criteria.md` US-003 requires Low, Medium, High, and Critical levels. `prototype/App.tsx` models verdicts as `safe`, `suspicious`, or `phishing`, and Sprint 4 describes Low Risk, Suspicious, and Phishing outcomes.

**Risk:** Acceptance criteria cannot be consistently marked passed without a shared tier definition.

**Recommended action:** Confirm the intended release taxonomy and score thresholds; update the acceptance criteria, UI labels, and test cases to use one consistent mapping.

**Verification / exit criterion:** Every supported verdict has a documented meaning and deterministic test cases, including boundaries.

### GAP-05 — Scope mismatch: message/email analysis versus URL-only prototype

**Priority:** Medium  
**Type:** Scope / requirements  
**Evidence:** US-001 requires submission and processing of suspicious email content; the reviewed `prototype/App.tsx` implements URL analysis. The README describes URL or message submission.

**Risk:** The team may report completion against requirements that the prototype does not implement.

**Recommended action:** Confirm whether email/message analysis is part of the current website MVP. If deferred, explicitly mark it out of scope or future work; if required, assign implementation and acceptance tests. Remove extension references from current-scope descriptions.

**Verification / exit criterion:** README, user stories, acceptance criteria, sprint board, and demo script agree on the current website-only MVP.

### GAP-06 — Security verification checklist not executed in the reviewed log

**Priority:** High  
**Type:** Security test evidence  
**Evidence:** `docs/DATA_PROTECTION.md` includes V1–V10 with blank actual-result and pass/fail columns. It also marks several controls Planned, including input length, storage, logging, security headers, dependency inventory, and production debug settings.

**Risk:** Security controls may be documented without evidence that they operate correctly.

**Recommended action:** Run V1–V10 against the actual running build, attach evidence, and add checks for HTTP response security headers, secret handling, dependency review, and deployment configuration. Reconcile tests with intended behavior; for example, V4 expects a clear blank-input error, while `handleCast` currently returns early on blank input without setting an error.

**Verification / exit criterion:** Each applicable control has a test ID, environment/build, observed result, evidence, status, and linked issue for failures.

### GAP-07 — URL input validation and edge-case coverage need strengthening

**Priority:** Medium  
**Type:** Negative / boundary testing  
**Evidence:** `analyzeUrl` validates schemes, hostnames, malformed strings, and ports through `URL` parsing. The reviewed code does not impose a maximum input length, although `docs/DATA_PROTECTION.md` lists a length cap as Planned. The IPv6 check tests bracket presence, relying on URL parsing for other validation.

**Risk:** Unusual inputs or oversized submissions may behave inconsistently, and a security requirement remains unverified.

**Recommended action:** Specify a maximum accepted length and test empty/whitespace, oversized URLs, invalid ports, URL credentials, IDN/punycode, IP literals, redirects, encoded content, fragments, malformed escapes, and non-HTTP schemes.

**Verification / exit criterion:** A repeatable boundary suite passes, with clear errors and no crashes or unsafe navigation.

### GAP-08 — Backend/API and production deployment status not established

**Priority:** Medium pending architecture confirmation  
**Type:** Integration / release-readiness evidence  
**Evidence:** The reviewed `prototype/App.tsx` calculates scores client-side and uses a `setTimeout` to simulate an analysis delay. No API invocation was established in that inspected file. The repository may contain other implementation artifacts or deployments that were not reviewed.

**Risk:** Tests of the local prototype alone do not verify any planned backend integration or deployed environment.

**Recommended action:** Confirm the production architecture and deployment URL with the team. If an API is required, add request/response, invalid-input, timeout, rate-limit, failure, and frontend/backend integration tests. If client-side-only, document that decision and remove unsupported backend claims.

**Verification / exit criterion:** Architecture is documented and the deployed application passes end-to-end smoke tests in the actual release environment.

### GAP-09 — Threat model documentation has stale and duplicate material

**Priority:** Low  
**Type:** Documentation maintenance  
**Evidence:** `docs/THREATS.md` contains duplicate section numbers and sections describing equal-weighted scoring, although Sprint 3 changed the scoring to weighted heuristics. The README still calls the extension a stretch goal.

**Risk:** Reviewers may mistake superseded controls or risks for current implementation.

**Recommended action:** Consolidate duplicate threat entries, mark historical risks as mitigated or still open, update verification text, and remove extension references from current-scope documentation.

**Verification / exit criterion:** Threat register reflects the current implementation, each risk has a unique identifier, and the README agrees with the approved scope.

## 4. Suggested QA execution plan

| Sequence | Deliverable | Suggested location | Owner / dependency |
|---|---|---|---|
| 1 | Privacy decision and storage verification | `docs/Testing/` and relevant GitHub Issue | QA + frontend developer |
| 2 | Updated scope and risk-tier acceptance criteria | `docs/Requirements/Acceptance_Criteria.md` | Product owner + QA |
| 3 | Security verification V1–V10 with evidence | `docs/Testing/` | QA; requires running build |
| 4 | Detection accuracy evaluation | `docs/Testing/` | QA + scoring developer |
| 5 | Integration and production smoke tests | `docs/Testing/` | QA + deployment owner |
| 6 | Release-readiness sign-off | `docs/Testing/` | Team review |

## 5. Proposed minimum release gate

Before calling the website release-ready, the team should agree on and record all of the following:

- Current MVP scope and risk tiers are approved and match the implementation.
- No unresolved critical security/privacy defects; high-severity issues have an explicit team disposition.
- V1–V10 are executed or formally marked not applicable with justification.
- Representative accuracy metrics and limitations are reported, not inferred from a few demonstration URLs.
- Demonstration-only threat intelligence is clearly disclosed unless a maintained source is integrated.
- Actual deployment passes navigation, URL validation, scan, results, error handling, and mobile smoke tests.
- HTTPS, security headers, dependency review, and secret-handling checks are recorded for the deployed environment.
- Each failed test links to a tracked defect, with retest evidence before closure.

## 6. QA status and limitations

**Assessment status:** Initial gap analysis complete; remediation and live verification pending.  
**No application tests were executed as part of this analysis.** Prior sprint pass counts are team-reported. Findings from static inspection should be confirmed against the current deployed build and team-approved requirements before being closed or classified as confirmed defects.

**Recommended first issue:** `GAP-01 — Resolve persistent URL history versus no-storage privacy requirement`.
