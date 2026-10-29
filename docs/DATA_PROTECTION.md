# Data Protection and Security Standard Mapping
 
This document supports US13 (Sprint 3). It identifies the data PhishGuard handles that must be protected and maps our controls to the OWASP Application Security Verification Standard (ASVS) 4.0.3, which our team research already identified as the basis for testable requirements.
 
---
 
## 1. Data That Must Be Protected
 
| # | Data asset | Why it matters | How we protect it |
|---|------------|----------------|-------------------|
| D1 | **Submitted URLs** | Pasted links can carry secrets: login tokens, password-reset codes, or credentials in the URL (e.g. `user:password@host`). Users may also paste links from private emails. | Analyzed as text only, never opened or fetched. Not stored. Full URLs and query values are not logged. Credentials in the URL are masked when displayed. |
| D2 | **Scan results** (risk level, reasons, Sonar Analysis Log warnings) | Derived from D1 and can echo parts of it. | Rendered as plain text, not HTML. Not persisted after the scan. |
| D3 | **Known-bad list and scoring rules/weights** | If altered, the engine produces false negatives without anyone noticing. Integrity matters more than secrecy. The list is currently a demonstration list. | Kept under version control. Changes go through pull-request review. Source of the known-bad list is documented. |
| D4 | **Usability test participant data** (notes, responses, any identifying details) | Personal data about real people. The GitHub repository is public. | Participants recorded as P1-P5 only. No names or recordings in the repo. Raw notes kept outside the repo, only anonymized results committed. |
| D5 | **Credentials and API keys** (for any known-bad list service) | A leaked key can be abused or revoked. | Environment variables only. Covered by `.gitignore`. Never committed (Risk Assessment R8). |
 
---
 
## 2. ASVS 4.0.3 Mapping
 
Status key: **Planned** = design decision recorded, to be confirmed in code review. **Verify** = covered by a QA test case.
 
| ASVS | Requirement (summary) | PhishGuard control | Data | Status |
|------|----------------------|--------------------|------|--------|
| 5.1.3 | Validate all input with allow lists | Accept only well-formed `http`/`https` URLs; reject everything else with a clear message | D1 | Verify (invalid/blank input cases) |
| 5.1.4 | Structured data typed and validated, including length | Parse with the URL API; cap input length | D1 | Planned |
| 5.2.6 | Protect against SSRF; allow lists of protocols and domains | The analyzer never fetches submitted URLs; only `http`/`https` schemes accepted | D1 | Verify (no auto-open test) |
| 5.1.5 | Redirects only to allow-listed destinations or with a warning | Shortened links are not expanded and redirects are not followed; redirect parameters are flagged as a warning signal | D1 | Planned |
| 5.2.4 | Avoid `eval()` and dynamic code execution | No `eval()` or dynamic code on submitted input | D1 | Planned |
| 5.3.3 | Context-aware output escaping against XSS | Submitted URL and reasons rendered as text; suspicious links displayed non-clickable | D1, D2 | Verify (script-string test) |
| 8.3.1 | Sensitive data not sent in the query string | Scanned URL is never placed in PhishGuard's own page URL | D1 | Planned |
| 8.2.2 | Browser storage holds no sensitive data | No `localStorage`/`sessionStorage`/cookies containing submitted URLs | D1, D2 | Planned |
| 8.3.4 | Sensitive data identified and a handling policy exists | This document | D1-D5 | Done |
| 8.3.8 | Data retention classification | Nothing persisted; participant data anonymized | D1, D4 | Planned |
| 7.1.1 / 7.1.2 | Do not log credentials or other sensitive data | Log check outcomes only, never full URLs or query values | D1 | Planned |
| 7.4.1 | Generic message on unexpected errors | Friendly error messages; no stack traces shown to users | D1 | Verify (invalid input cases) |
| 14.3.2 | Debug modes disabled in production | Debug off on the deployed app | D2 | Planned |
| 14.4.3 / 14.4.4 / 14.4.6 | CSP, `nosniff`, and Referrer-Policy headers | Set when the app is deployed, so scanned URLs are not leaked through the Referer header | D1 | Planned |
| 8.1.4 | Detect abnormal request volumes | Rate limiting on scans (Risk Assessment R9) | D2 | Planned |
| 14.1.5 | Verify integrity of security-relevant configuration | Scoring rules and known-bad list changes tracked in Git history | D3 | Planned |
| 14.2.1 / 14.2.5 | Keep components up to date; maintain a component inventory | Dependency list maintained in the README; dependencies updated before the demo | D5 | Planned |
 
---
 
## 3. Notes and Open Items
 
- The application code (named in the Sprint 3 test notes as `artifacts/phish-detector/src/App.tsx`) is not yet in the repository, so every "Planned" row must be confirmed against the actual code before it can be marked verified.
- ASVS requirement numbers are from version 4.0.3. Version 5.0 renumbers chapters, so the team should keep citing 4.0.3 unless it deliberately switches.
- Items tied to authentication, sessions, and user accounts are out of scope because PhishGuard has no logins (see Boundary of Scope).
- Usability testing introduces D4. Add a note to the test script telling participants not to enter real personal links.
---
 
## 4. Verification Log
 
Complete this table once the application code is available. Mark each ASVS row in section 2 as verified only if its test passes.
 
| # | Test | Input | Expected result | Actual result | Pass/Fail |
|---|------|-------|-----------------|---------------|-----------|
| V1 | Submitted URL is not opened | `http://example.com` | Result shown, no navigation to the URL | | |
| V2 | Script string is inert | `javascript:alert(1)` | Rejected or shown as plain text, nothing runs | | |
| V3 | Markup is inert | `<script>alert(1)</script>` | Rejected or shown as plain text, nothing runs | | |
| V4 | Blank input | (empty) and spaces only | Clear error message, no scan | | |
| V5 | Invalid input | `not-a-url`, `http://` | Clear error message, no stack trace | | |
| V6 | Credentials masked | `http://user:password@example.com` | Password not shown in full on screen | | |
| V7 | Query values not stored or logged | `https://example.com/?token=abc123` | Token not in logs, browser storage or page URL | | |
| V8 | Scanned URL not in page address | Any scan | PhishGuard's own page URL does not contain the scanned URL | | |
| V9 | Shortened link not expanded | `https://bit.ly/example` | Analyzed as text, no request to the destination | | |
| V10 | Weak signals combined | HTTP + `.xyz` + shortener | Score escalates above Low Risk | | |
 
