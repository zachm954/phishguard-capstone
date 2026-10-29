# Mitigation and Contingency Plans
 
This document supports US17 (Sprint 4). For each of PhishGuard's main risks it records the **mitigation** (what we do to prevent or reduce the risk), the **trigger** (the observation that tells us the mitigation is not enough), and the **contingency** (what we do if the trigger happens). Mitigations come from [THREATS.md](THREATS.md) and [DATA_PROTECTION.md](DATA_PROTECTION.md). Triggers are tied to the success measures stated before development: at least 90% of predefined QA cases pass, at least 4 of 5 usability participants complete the scan flow unassisted, and 100% of submitted URLs are handled without being opened.
 
Owners are the team members responsible for acting if a trigger occurs.
 
---
 
## 1. False positives: legitimate URLs flagged as risky
 
- **Mitigation:** Severity-based weights across the 12 checks, so a weak signal alone does not raise the verdict. After the Sprint 3 change, `https://bit.ly/example` (TC03) scores 5 (Low Risk) instead of Suspicious.
- **Trigger:** A legitimate URL that triggers several weak indicators is rated Suspicious or Phishing during QA or usability testing.
- **Contingency:** Adjust the weights or thresholds for the checks involved and re-run the full test list to confirm nothing else changed. Record each change and the reason in the test evidence.
- **Owner:** Zachariah Omar Melendez-Martinez
## 2. False negatives and over-trust in a Low Risk result
 
- **Mitigation:** The result wording says "Low Risk Detected," not "Safe." Every verdict is shown with the reasons behind it, and the interface never claims a link is guaranteed safe.
- **Trigger:** A usability participant treats Low Risk as "safe to click," or a known-malicious test URL receives Low Risk.
- **Contingency:** Add a visible reminder next to every Low Risk result that detection is not a guarantee, and tell users to verify the sender separately. Add the missed URL pattern as a new check or a QA test case.
- **Owner:** Jade Xavier Garcia (wording), Zachariah Omar Melendez-Martinez (new checks)
## 3. Known-bad list covers only demonstration entries
 
- **Mitigation:** The known-bad check works against a local demonstration list. The team decides a real list source this sprint and documents it.
- **Trigger:** No maintained list source can be integrated before the final sprint.
- **Contingency:** State the limitation plainly in the demo and final report, with no claim of real-world known-bad coverage. Rely on the heuristic checks and describe the known-bad check as a proof of concept.
- **Owner:** Zachariah Omar Melendez-Martinez
## 4. A submitted URL is opened or fetched by mistake
 
- **Mitigation:** URLs are analyzed as text only. Shortened links are not expanded, redirects are not followed, and suspicious links are not displayed as clickable links.
- **Trigger:** Any test shows a submitted URL being opened, fetched, or rendered as a working link. The success measure is 100% handled without being opened, so one failure counts.
- **Contingency:** Treat it as a release blocker. Remove or disable the feature that causes it before any demo, fix the cause, and re-run the safety tests.
- **Owner:** Zachariah Omar Melendez-Martinez
## 5. Script or markup in a submitted URL runs when displayed
 
- **Mitigation:** Submitted input and result text are rendered as plain text with escaping, and only `http` and `https` URLs are accepted.
- **Trigger:** A test string such as `javascript:alert(1)` or a `<script>` tag executes or appears as active content.
- **Contingency:** Switch all submitted-input display to plain text only until the fix is verified. Do not demo with the affected view.
- **Owner:** Jade Xavier Garcia (display), Alicia Auxiliadora Giro (verification)
## 6. Sensitive data or participant information ends up in the public repository
 
- **Mitigation:** Full URLs and query values are not stored or logged. Participants are recorded as P1–P5 only, raw notes stay outside the repo, and credentials are kept in environment variables covered by `.gitignore`.
- **Trigger:** A name, contact detail, token, or API key is found in a committed file.
- **Contingency:** Remove the data and commit the fix immediately. If a key or token was committed, revoke and replace it, because deleting the file does not remove it from history. Tell the team lead so the exposure is recorded.
- **Owner:** Luis Felipe Nicaragua (participant data), Alicia Auxiliadora Giro (repo check)
## 7. Schedule risk: code or test evidence arrives too late
 
- **Mitigation:** The application code is pushed to the repository early in the sprint, and the usability sessions are scheduled in the first week.
- **Trigger:** The code is not in the repo by the middle of the sprint, or fewer than five usability sessions are completed.
- **Contingency:** Raise it in the team channel and with the Product Owner right away. Mark any security control that could not be checked against code as "unverified" and say so in the documents, instead of reporting it as verified. If fewer than five participants complete the test, report the actual number and recompute the pass rate honestly, noting that the 4-of-5 target was not tested as planned.
- **Owner:** Luis Felipe Nicaragua
## 8. The live demo fails
 
- **Mitigation:** The README documents how to run the application from the repository, which the must-ship deliverables allow in place of a hosted URL.
- **Trigger:** The deployed application is unavailable, or the run steps fail on a clean machine before the final demo.
- **Contingency:** Run the demo locally from the repo using the documented steps, and keep screenshots and a recorded walkthrough of a full scan as a backup.
- **Owner:** Onyenka Robert Okoh
---
 
## Review
 
This plan is reviewed at the end of each sprint. Any trigger that occurs is recorded with the action taken, and the related entry in `THREATS.md` is updated.
