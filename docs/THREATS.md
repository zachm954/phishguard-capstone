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

Verification for Threats 1 and 2 can now be executed against the implemented multi-check scoring engine (US7). Verification for Threat 5 is confirmed by Sprint 2 US7 test results (see docs/Testing/Sprint_2_US7_Testing/) — TC03 shows a legitimate shortened URL flagged Suspicious.
