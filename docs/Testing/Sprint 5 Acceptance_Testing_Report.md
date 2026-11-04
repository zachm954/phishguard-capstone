# PhishGuard — Capstone 2 Acceptance Testing Report

**Test date:** November 3, 2026  
**Project:** PhishGuard — Web-based phishing URL analyzer  
**Testing type:** Manual, black-box UI acceptance and heuristic-conformance checks  
**Tester role:** QA / requirements and testing  
**Evidence:** Screenshots collected during each test; screenshots will be uploaded separately to GitHub.  
**Overall status:** 8/8 targeted checks passed; follow-up recommendations remain

## 1. Purpose and scope

Verify that PhishGuard accepts selected URL inputs, displays an overall risk score and verdict, and flags the expected URL-based indicators. Tests use legitimate URLs and controlled/example inputs. These are **not** independently labeled real-world phishing detection accuracy measurements, penetration tests, or backend verification. No suspicious destination was intentionally opened during testing.

## 2. Executive results

| ID | Scenario | Expected behavior | Observed behavior | Score | Result |
|---|---|---|---|---:|---|
| ACC-01 | Legitimate HTTPS — Google | Low Risk; no indicators triggered | Low Risk Detected; no red checks observed | 0/100 | **PASS** |
| ACC-02 | Legitimate HTTPS — GitHub | Low Risk; no indicators triggered | Low Risk Detected; no red checks observed | 0/100 | **PASS** |
| ACC-03 | HTTP transport warning | No HTTPS warning; low phishing risk | No HTTPS red; Low Risk Detected | 5/100 | **PASS** |
| ACC-04 | Uncommon top-level domain | Suspicious TLD warning; low overall risk | Suspicious TLD red; Low Risk Detected | 5/100 | **PASS** |
| ACC-05 | Lookalike brand and login lure | Brand, phishing keywords and HTTP warnings; phishing verdict | Brand Impersonation, Phishing Keywords, No HTTPS red; Phishing Hook Detected | 40/100 | **PASS** |
| ACC-06 | Local known-bad demo match | Known-Bad warning and phishing verdict | Known-Bad URL/Domain and Phishing Keywords red; Phishing Hook Detected | 100/100 | **PASS** |
| ACC-07 | Brand lookalike with HTTPS | Brand impersonation warning; suspicious verdict | Brand Impersonation red; Suspicious Bait | 25/100 | **PASS** |
| ACC-08 | Redirect query parameter | Redirect Parameters warning | Redirect Parameters and Phishing Keywords red; Low Risk Detected | 20/100 | **PASS** |

**Summary:** 8 executed; 8 passed their targeted checks; 0 failed; 0 blocked. The pass rate describes this limited functional suite, **not** phishing-detection accuracy on a representative dataset.

## 3. Detailed test evidence and observations

### ACC-01 — Legitimate HTTPS — Google

- **Input:** `https://www.google.com`
- **Expected:** Low Risk; no indicators triggered.
- **Actual:** Low Risk Detected; no red checks observed. Risk score **0/100**.
- **Result:** **PASS** — expected targeted indicator/classification behavior observed.
- **QA notes:** All visible checks were green. The application accepted the HTTPS URL and returned a score of 0.

**Screenshots:** Screenshots will be added separately on GitHub.

### ACC-02 — Legitimate HTTPS — GitHub

- **Input:** `https://www.github.com`
- **Expected:** Low Risk; no indicators triggered.
- **Actual:** Low Risk Detected; no red checks observed. Risk score **0/100**.
- **Result:** **PASS** — expected targeted indicator/classification behavior observed.
- **QA notes:** All visible checks were green across the scrolled analysis log. Score remained 0.

**Screenshots:** Screenshots will be added separately on GitHub.

### ACC-03 — HTTP transport warning

- **Input:** `http://example.com`
- **Expected:** No HTTPS warning; low phishing risk.
- **Actual:** No HTTPS red; Low Risk Detected. Risk score **5/100**.
- **Result:** **PASS** — expected targeted indicator/classification behavior observed.
- **QA notes:** The `No HTTPS` check was red, adding 5 points, but the overall verdict remained Low Risk. A low phishing-risk verdict does not imply encrypted transport.

**Screenshots:** Screenshots will be added separately on GitHub.

### ACC-04 — Uncommon top-level domain

- **Input:** `https://example.xyz`
- **Expected:** Suspicious TLD warning; low overall risk.
- **Actual:** Suspicious TLD red; Low Risk Detected. Risk score **5/100**.
- **Result:** **PASS** — expected targeted indicator/classification behavior observed.
- **QA notes:** The `.xyz` TLD check was red, with a 5-point score. A TLD alone is not proof of maliciousness.

**Screenshots:** Screenshots will be added separately on GitHub.

### ACC-05 — Lookalike brand and login lure

- **Input:** `http://secure-login.paypa1.com`
- **Expected:** Brand, phishing keywords and HTTP warnings; phishing verdict.
- **Actual:** Brand Impersonation, Phishing Keywords, No HTTPS red; Phishing Hook Detected. Risk score **40/100**.
- **Result:** **PASS** — expected targeted indicator/classification behavior observed.
- **QA notes:** Three warnings were visibly red: `Brand Impersonation`, `Phishing Keywords`, and `No HTTPS`. `Known-Bad URL/Domain` did not match. The score was 40 and the verdict was phishing.

**Screenshots:** Screenshots will be added separately on GitHub.

### ACC-06 — Local known-bad demo match

- **Input:** `https://malicious.example.test/login`
- **Expected:** Known-Bad warning and phishing verdict.
- **Actual:** Known-Bad URL/Domain and Phishing Keywords red; Phishing Hook Detected. Risk score **100/100**.
- **Result:** **PASS** — expected targeted indicator/classification behavior observed.
- **QA notes:** `Known-Bad URL/Domain` and `Phishing Keywords` were red. `No HTTPS` remained green. This is a configured local demonstration match, not an independent threat-intelligence finding.

**Screenshots:** Screenshots will be added separately on GitHub.

### ACC-07 — Brand lookalike with HTTPS

- **Input:** `https://paypa1.com`
- **Expected:** Brand impersonation warning; suspicious verdict.
- **Actual:** Brand Impersonation red; Suspicious Bait. Risk score **25/100**.
- **Result:** **PASS** — expected targeted indicator/classification behavior observed.
- **QA notes:** `Brand Impersonation` was red; HTTPS passed. The score was 25 and the verdict was Suspicious Bait. This confirms the specific lookalike rule fired, not the real-world status of the domain.

**Screenshots:** Screenshots will be added separately on GitHub.

### ACC-08 — Redirect query parameter

- **Input:** `https://example.com/login?next=https://example.org`
- **Expected:** Redirect Parameters warning.
- **Actual:** Redirect Parameters and Phishing Keywords red; Low Risk Detected. Risk score **20/100**.
- **Result:** **PASS** — expected targeted indicator/classification behavior observed.
- **QA notes:** `Redirect Parameters` and `Phishing Keywords` were red, but the overall verdict remained Low Risk Detected at 20. The redirect indicator works; the severity threshold deserves product review.

**Screenshots:** Screenshots will be added separately on GitHub.

## 4. Findings and follow-up actions

| Finding | Priority | Recommendation |
|---|---|---|
| ACC-08 returned **Low Risk** despite redirect and login keyword warnings | Medium | Review scoring thresholds and clarify whether two warnings should produce Suspicious status; do not treat as a confirmed defect without approved thresholds |
| Generic explanatory text is shown even for green/passed checks | Low | Add explicit “Not detected” or “Passed” state labels to avoid confusing users |
| ACC-03 HTTP URL returned Low Risk | Medium | Distinguish phishing risk from transport encryption; warn users not to submit credentials over HTTP |
| ACC-06 known-bad match is based on a local demo list | High | Do not describe this as live threat-intelligence detection; document demo-only behavior and production requirements |
| Small, hand-picked suite does not measure accuracy | High | Test an independently labeled, representative benign/phishing dataset and calculate TP, TN, FP, FN, precision, recall, specificity, and false-positive rate |
| Risk labels in earlier acceptance criteria may not match UI labels | Medium | Reconcile documented Low/Medium/High/Critical levels with Low Risk/Suspicious Bait/Phishing Hook Detected before release |

## 5. Evidence and reproducibility

Screenshots for each `ACC-XX` case will be added separately on GitHub to keep this report file small. The screenshots document the displayed verdict, risk score, and scrolled Sonar Analysis Log. Suggested evidence filenames are `ACC-XX_01.png` and so on. To reproduce, open the PhishGuard web interface, paste the exact test URL into the URL field, select **Cast the Line**, and review the score and each relevant log indicator. Screenshots establish observed UI behavior at the time of testing; they do not independently prove backend behavior, URL reputation, or security guarantees.

## 6. Final QA conclusion

**Conditional acceptance of the eight targeted UI/heuristic checks.** All eight tested inputs produced the expected targeted indicators, and the observed scores/verdicts are documented. This is sufficient evidence of this specific functional test suite passing, but **not** a production-readiness sign-off. Prioritize clarifying the ACC-08 severity threshold, documenting the local-demo blocklist, aligning acceptance criteria with implemented risk labels, and performing representative detection-accuracy and security testing before claiming real-world phishing protection.

**Report prepared from tester-provided screenshots, November 3, 2026.**
