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

*Note: Verification steps for Threats 1 and 2 will be executed once US2's core scoring logic is implemented.*
