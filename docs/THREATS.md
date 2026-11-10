# Threats, Controls, and Verification
 
PhishGuard has to be trustworthy in how it operates, not just accurate in what it flags. This document names the ways PhishGuard itself could fail or be exploited, the control we're putting in place for each, and how we'll verify that control holds.
 
---
 
## 1. Malicious URL Exploiting the Analyzer
 
**Threat:** A submitted URL could be crafted to exploit the analyzer itself, rather than simply looking suspicious (e.g., a payload designed to break the scanner).
 
**Control:** Never fetch or render submitted URLs directly. The analyzer only examines structure, metadata, and known-bad-list matches — it never opens a link server-side or client-side.
 
**Verification:** Test the analyzer against a known malformed or exploit-style URL and confirm it returns a risk level without attempting to load the link.
 
**Status (11/10/2026):** Verified by code review of `prototype/App.tsx`: the analyzer only parses the URL text and makes no network calls. A runtime check with network monitoring is still recommended.
 
---
 
## 2. Look-Alike / Typosquatted Domain
 
**Threat:** A look-alike or typosquatted domain (e.g., `paypa1.com`) could fool our own detection signals.
 
**Control:** Cross-check submitted domains against a known-bad list and common typosquatting patterns, rather than relying on any single signal.
 
**Verification:** Run a set of known look-alike domains through the analyzer and confirm each is correctly flagged medium or high risk.
 
---
 
## 3. User Over-Trusting a Wrong Verdict
 
**Threat:** A user could over-trust a wrong verdict — clicking a link PhishGuard rated as low risk when it wasn't (false negative).
 
**Control:** Pair every verdict with the specific reasons behind it, not just a score, so users learn what to look for themselves rather than blindly trusting a label.
 
**Verification:** Usability testing — confirm participants can name a red flag independent of the score, not just repeat the risk level back.
 
**Status (11/10/2026):** The result wording is "Low Risk Detected," not "Safe," and every verdict lists the checks that fired. The usability test that confirms participants can name a red flag has not been completed.
 
---
 
## 4. PhishGuard's Own Data / Permissions Footprint
 
**Threat:** PhishGuard's own permissions or data footprint could become a target (e.g., an attacker exploiting extension permissions to access more than intended).
 
**Control:** Collect no personal data, require no login, and store no scan history — nothing exists on our end for an attacker to target.
 
**Verification:** Code review confirming no user data is persisted or transmitted beyond the scan itself.
 
**Status (11/10/2026):** Does not currently meet the control. The application saves the last five submitted URLs in browser storage (`phishfinder_history`). Nothing is sent to a server, but the data stays on the user's device. Remediation: store only the hostname or remove the history (US20), or document it as a known limitation.
 
---
 
## 5. Equal-Weighted Checks Causing False Positives
 
**Threat:** The scoring engine runs 12 checks, all weighted equally, with the verdict based on how many are flagged (0 = Safe, 1-2 = Suspicious, 3+ = Phishing). A legitimate URL can be flagged from a single weak signal such as length, a shortener, or a redirect parameter, which erodes user trust.
 
**Control:** Weight strong signals (e.g., brand impersonation, known-bad-list match) more heavily than weaker ones (e.g., URL length, shorteners), and keep showing which specific checks fired so the verdict can be inspected.
 
**Verification:** Re-run the Sprint 2 cases and a set of known-legitimate URLs that trigger weak signals. Sprint 2 test TC03 (`https://bit.ly/example`) was flagged Suspicious on the shortener check alone. After the Sprint 3 reweighting it scores 5 (Low Risk), and the shortener is still flagged and explained. Further testing is still needed on legitimate URLs that trigger several weak indicators at once.
 
---
 
## 6. Sensitive Data Inside Submitted URLs
 
**Threat:** Users may paste links that contain secrets, such as password-reset tokens, session tokens, or credentials in the URL (user:password@host). Storing, logging, or echoing them would expose that data.
 
**Control:** Do not store or log full submitted URLs or query values, mask credentials when displaying a URL, and never place the scanned URL in PhishGuard's own page address. Tell users not to submit links that contain personal information.
 
**Verification:** Submit a URL containing user:password@ and ?token=..., then confirm the values do not appear in logs, browser storage, or PhishGuard's page URL, and that credentials are masked on screen.
 
**Status (11/10/2026):** Does not currently meet the control. Code review found that the full URL, including query values, is saved in browser storage, and that credentials in `user:password@host` are shown unmasked in the result. Remediation: mask credentials on screen and stop storing full URLs.
 
---
 
## 7. Output Injection Through Displayed URLs
 
**Threat:** A submitted URL or string could contain script or markup (e.g., javascript: links or <script> text) that runs or becomes clickable when PhishGuard displays it.
 
**Control:** Render submitted input and result text as plain text with context-aware escaping, display suspicious links as non-clickable text, and accept only http/https URLs.
 
**Verification:** Submit javascript:alert(1) and a string containing <script> tags, then confirm they are rejected or displayed inertly and nothing executes.
 
**Status (11/10/2026):** Verified by code review: result text is rendered as plain text, there are no clickable links, and `javascript:` and markup strings are rejected. A runtime test is still recommended.
 
---
 
## 8. Tampering With the Known-Bad List or Scoring Rules
 
**Threat:** If the known-bad list or scoring rules are altered, whether by accident or by an unauthorized change, the engine could miss real phishing links without any visible error.
 
**Control:** Keep the list and scoring rules under version control, require pull-request review for changes, and document the source of the known-bad list.
 
**Verification:** Review the Git history for the rules and list to confirm every change is attributable and reviewed, and re-run a known-bad test URL after any change to confirm it is still flagged.
 
---
 
## 9. Exposure of Usability Test Participant Data
 
**Threat:** Notes or responses from usability participants could expose personal information if committed to the public repository.
 
**Control:** Record participants as P1–P5 only, keep raw notes outside the repository, and commit only anonymized results.
 
**Verification:** Before committing test results, search the repository for participant names or contact details and confirm none are present.
 
---
 
## 10. Reweighting Lets Phishing Built From Weak Signals Through
 
**Threat:** After the Sprint 3 reweighting, tests TC02 (no HTTPS), TC03 (URL shortener) and TC05 (suspicious TLD) each score 5 and are rated Low Risk. A phishing URL built only from weak signals, with no brand name or phishing keyword, may stay Low Risk even though several of its indicators fire together.
 
**Control:** Add combination rules, like the existing rule that escalates brand impersonation plus phishing keywords, for common groups of weak signals, and review the thresholds against the full test list. Keep the "Low Risk Detected" wording so a low score is never presented as a guarantee of safety.
 
**Verification:** Submit URLs that combine several weak signals (for example HTTP, a suspicious TLD, a shortener, and a redirect parameter) and confirm the score rises above Low Risk. Record each result in the test evidence.
 
**Status (11/10/2026):** Partly verified. TC13 (several weak indicators) scores 25 and is Suspicious, so a combination rule exists. TC08 (several phishing keywords) scores 10 and stays Low Risk, so keyword-only phishing can still be rated Low Risk.
 
---
 
## 11. Demonstration Known-Bad List Gives False Assurance
 
**Threat:** The known-bad check currently uses a local demonstration list, so a malicious URL that is not on the list gets no help from it. Users or reviewers could assume the check covers real-world threats.
 
**Control:** Label the list as a demonstration in the documentation and the demo, decide a real list source, and never describe the check as real-world coverage until one is integrated.
 
**Verification:** Review the README, the final report and the demo script for any claim of real-world known-bad coverage, and confirm a URL that is not on the list is still scored by the other checks.
 
---
 
Verification for Threats 1, 2, 5 and 10 can be run against the Sprint 3 scoring engine once the application code is in the repository. Threats 6–9 were added in Sprint 3 (US13), and Threats 10–11 in Sprint 4 (US17) from the Sprint 3 test evidence.
 
