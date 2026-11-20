# Provenance and Ethics: Data Boundary, Ethics Considerations and AI-Use Disclosure
 
Team 107, PhishGuard. This part covers what data the project used, the ethical issues it raises, and where AI tools helped. The component and licence inventory and the verified references are filed separately on the capstone site.
 
---
 
## 1. Data Boundary
 
**What PhishGuard works with.** PhishGuard analyzes the text of a URL that a user types in. It never opens, fetches or renders the link, so it handles no web page content, and the analysis uses 12 rule-based checks. It uses no machine-learning model and no training dataset.
 
**Data used in building and testing the project:**
- **Test URLs.** Public example addresses and reserved test addresses (for example `example.com`, `example.xyz`, `paypa1.com` used as a lookalike example, and `malicious.example.test`, a reserved `.test` name that cannot belong to a real site). No real victim data and no real phishing links collected from the wild.
- **Known-bad list.** A small local demonstration list of reserved `.test` entries. It is not a threat-intelligence feed. URLhaus has been identified as a candidate source but is not integrated.
- **Usability participants.** Participants are recorded as P1–P5 only, with no names or contact details in the repository.
**Data the project does not use or collect:** no personal data, no logins or accounts, no server-side storage, no analytics, and no scan history sent anywhere.
 
**Known gaps, found in our own verification (11/10/2026).** The application saves the last five submitted URLs in the user's own browser storage, which can include query values, and it shows credentials in a submitted URL unmasked. Nothing leaves the device, but this goes beyond the "store nothing" boundary above. It is recorded as an open finding in DATA_PROTECTION.md and RISK_MANAGEMENT_AND_RECOVERY.md, with the planned fix (store only the hostname and mask credentials).
 
---
 
## 2. Ethics Considerations
 
1. **False assurance.** A user who sees Low Risk may treat the link as safe. In our own tests, links with several weak warning signs still scored Low Risk. The interface says "Low Risk Detected," not "Safe," shows the reasons behind every result, and the limitations statement says plainly that a low score is not a guarantee.
2. **Unfair false positives.** The checks are heuristic and lean on signals such as unusual domain endings, shorteners and long URLs. A small business or an individual using a legitimate but unusual domain could be flagged as suspicious. The weights were tuned so one weak signal does not condemn a link, and every flag is explained so a user can judge it.
3. **People submitting sensitive links.** Users may paste links that contain tokens or passwords. The app does not send them anywhere, but the user should be warned not to submit links containing personal information, and the app does not yet show such a warning. The browser-history storage and unmasked credentials are open findings, recorded in DATA_PROTECTION.md with a planned fix.
4. **Misuse by someone evading detection.** The scoring rules and weights are public in the repository, so someone could test a phishing link until it scores Low Risk. We state this limitation and describe PhishGuard as a learning aid, not a security control.
5. **Safe handling.** Submitted links are never opened by the analyzer, so checking a dangerous link cannot expose the user or the team to it.
6. **Participant welfare.** The usability records in the repository identify participants as P1 to P5 only, with no names or contact details. The session results themselves are still being recorded.
7. **Honest claims.** The team does not claim live threat-intelligence coverage, measured detection accuracy or completed fixes that have not been verified.
---
 
## 3. AI-Use Disclosure
 
The team remains responsible for everything it submits. AI tools were used as follows. Each entry names who used the tool and who checked the output.
 
**Zachariah Melendez: Claude (Anthropic).**
- Used for research and development, mainly the URL risk analysis and scoring in `App.tsx`: the 12 security checks, the weighted risk scoring, and the known-bad URL and domain detection.
- **Checked by:** Zach reviewed the code and adjusted it in Replit, then tested it manually with test cases TC01 to TC05. He confirmed the bit.ly false positive was resolved, the fake PayPal URL was flagged, and the known-bad test entry scored 100. Results and screenshots are in `docs/Testing`.

---

**Luis Nicaragua: Claude (Anthropic).**
- Used for organizing the team's work and for research.
- **Checked by:** Luis reviewed the output himself and confirmed that he checked everything he took from Claude.

---

**Alicia Giro: Claude (Anthropic).**
- Used for documentation (sprint and security documents) and for security review of the application code. 
- **Checked by:** Alicia read each document, and the ASVS requirement numbers were checked against the OWASP ASVS 4.0.3 text. Claims about test results were checked against the test documents in the repository.

---

**Jade Garcia: Replit (AI features).**
- Used mainly for templating and ideas for the application. Jade made minor coding adjustments by hand.
- **Checked by:** Jade checked the output manually.

---
 
**Onyenka Robert Okoh: ChatGPT (OpenAI).**
- Used for quality assurance and documentation: the QA gap analysis, refining acceptance criteria, organizing testing procedures, analyzing manually collected test results, compiling the Acceptance Testing Report, identifying security concerns, evaluating phishing detection limitations, organizing GitHub documentation, and planning future testing.
- **Checked by:** All acceptance tests were conducted manually. Onyenka used AI as a supplementary tool for analysis, documentation and project organization.

---

Anything an AI tool produced that the team could not explain or verify was removed or rewritten.
