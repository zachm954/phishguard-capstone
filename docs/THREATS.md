# Threats, Controls, and Verification

PhishGuard has to be trustworthy in how it operates, not just accurate in what it flags. This document names the ways PhishGuard itself could fail or be exploited, the control we're putting in place for each, and how we'll verify that control holds.

---

## 1. Malicious URL Exploiting the Analyzer

**Threat:** A submitted URL could be crafted to exploit the analyzer itself, rather than simply looking suspicious (e.g., a payload designed to break the scanner).

**Control:** Never fetch or render submitted URLs directly. The analyzer only examines structure, metadata, and known-bad-list matches — it never opens a link server-side or client-side.

**Verification:** Test the analyzer against a known malformed or exploit-style URL and confirm it returns a risk level without attempting to load the link.

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

---

## 4. PhishGuard's Own Data / Permissions Footprint

**Threat:** PhishGuard's own permissions or data footprint could become a target (e.g., an attacker exploiting extension permissions to access more than intended).

**Control:** Collect no personal data, require no login, and store no scan history — nothing exists on our end for an attacker to target.

**Verification:** Code review confirming no user data is persisted or transmitted beyond the scan itself.

---

## 4. Equal-Weighted Checks Causing False Positives

**Threat:** The scoring engine currently runs 12 checks (IP-as-host, suspicious TLD, excessive subdomains, brand impersonation, excessive URL length, phishing keywords, no HTTPS, URL shorteners, @ symbol, redirect parameters, character encoding, URL anomalies), all weighted equally, with a verdict based purely on count (0 = safe, 1–2 = suspicious, 3+ = phishing). Because every check counts the same regardless of how strong a signal it actually is, a legitimate URL could be flagged suspicious or phishing for reasons like length, a keyword match, a shortener, or a redirect parameter — signals that are common in legitimate URLs and not inherently malicious on their own. This risks eroding user trust if safe links are repeatedly over-flagged.

**Control:** Run a set of known-legitimate URLs that happen to trigger weaker signals (long URLs, shorteners, redirect parameters, common keywords) and confirm how often they're misclassified as suspicious or phishing; use these results to prioritize which checks need reweighting. Confirmed in Sprint 2 US7 testing: https://bit.ly/example, a legitimate URL-shortener link, was flagged "Suspicious" on the basis of the shortener check alone — demonstrating that a single weak signal is enough to move a safe link out of the "Safe" tier under the current equal-weighting scheme.

**Verification:** Code review confirming no user data is persisted or transmitted beyond the scan itself.

---

## 5. Equal-Weighted Checks Causing False Positives

**Threat:** The scoring engine runs 12 checks, all weighted equally, with the verdict based on how many are flagged (0 = Safe, 1-2 = Suspicious, 3+ = Phishing). A legitimate URL can be flagged from a single weak signal such as length, a shortener, or a redirect parameter, which erodes user trust.

**Control:** Weight strong signals (e.g., brand impersonation, known-bad-list match) more heavily than weaker ones (e.g., URL length, shorteners), and keep showing which specific checks fired so the verdict can be inspected.

**Verification:** Re-run the Sprint 2 cases and a set of known-legitimate URLs that trigger weak signals. Sprint 2 TC03 (https://bit.li/example) was flagged Suspicious on the shortener check alone; after reweighting it should no longer be flagged on that signal by itself. 

---

## 6. Sensitive Data Inside Submitted URLs

**Threat:** Users may paste links that contain secrets, such as password-reset tokens, session tokens, or credentials in the URL (user:password@host). Storing, logging, or echoing them would expose that data.

**Control:** Do not store or log full submitted URLs or query values, mask credentials when displaying a URL, and never place the scanned URL in PhishGuard's own page address. Tell users not to submit links that contain personal information.

**Verification:** Submit a URL containing user:password@ and ?token=..., then confirm the values do not appear in logs, browser storage, or PhishGuard's page URL, and that credentials are masked on screen.

---

## 7. Output Injection Through Displayed URLs

**Threat:** A submitted URL or string could contain script or markup (e.g., javascript: links or <script> text) that runs or becomes clickable when PhishGuard displays it.

**Control:** Render submitted input and result text as plain text with context-aware escaping, display suspicious links as non-clickable text, and accept only http/https URLs.

**Verification:** Submit javascript:alert(1) and a string containing <script> tags, then confirm they are rejected or displayed inertly and nothing executes.

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

Verification for Threats 1, 2, and 5 can now be run against the multi-check scoring engine from Sprint 2 (US7). Threats 6–9 were added in Sprint 3 (US13).
