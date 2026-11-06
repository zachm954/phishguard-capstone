# Risk Management and Recovery Plan

This document supports US21 (Sprint 5). It turns the Sprint 4 [mitigation and contingency plans](MITIGATION_AND_CONTINGENCY.md) into a plan someone else on the team could pick up and operate. Part 1 rates each risk and assigns an owner and review point. Part 2 gives step-by-step recovery procedures for the four situations most likely to stop the project. Part 3 records the current status of risks found while verifying the controls against `prototype/App.tsx`.

Ratings use the scale from the [Risk Assessment](Project_Planning/Risk_Assessment.md): likelihood and impact are each Low, Medium, or High. Related entries are in [THREATS.md](THREATS.md) and [DATA_PROTECTION.md](DATA_PROTECTION.md).

---

## 1. Risk Register

| ID | Risk | Likelihood | Impact | Rating | Owner | Review |
|----|------|------------|--------|--------|-------|--------|
| RM1 | Legitimate URLs flagged as risky (false positives) | Medium | Medium | Medium | Zachariah Omar Melendez-Martinez | Each sprint review |
| RM2 | Phishing rated Low Risk, or users over-trust a Low Risk result (false negatives) | High | High | High | Zachariah Omar Melendez-Martinez, Jade Xavier Garcia | Each sprint review |
| RM3 | Known-bad list covers only demonstration entries | High | Medium | High | Zachariah Omar Melendez-Martinez | Before final report |
| RM4 | A submitted URL is opened or fetched by mistake | Low | High | Medium | Zachariah Omar Melendez-Martinez | Before every demo |
| RM5 | Script or markup in a submitted URL runs when displayed | Low | High | Medium | Jade Xavier Garcia, Alicia Auxiliadora Giro | Before every demo |
| RM6 | Sensitive data or participant information committed to the public repository | Medium | High | High | Luis Felipe Nicaragua, Alicia Auxiliadora Giro | Before every commit of test results |
| RM7 | Submitted URLs kept in browser storage (`phishfinder_history`) | High | Medium | High | Zachariah Omar Melendez-Martinez (fix), Alicia Auxiliadora Giro (verify) | Until resolved |
| RM8 | Code or test evidence arrives too late for verification | Medium | Medium | Medium | Luis Felipe Nicaragua | Each sprint review |
| RM9 | Live demo fails or the app cannot be run by someone else | Medium | High | High | Onyenka Robert Okoh | Before final demo |
| RM10 | A team member becomes unavailable | Medium | Medium | Medium | Luis Felipe Nicaragua | Each sprint review |

A risk rated High is reviewed first at every sprint review. A risk is closed only when its trigger has been checked and the result is written in the evidence, not when someone believes it is fixed.

---

## 2. Recovery Procedures

Each procedure says how to recognize the problem, what to do, and how to confirm the recovery worked. Anyone on the team can run them.

### 2.1 The application will not run or the hosted page is down

1. Confirm the problem on a second device or browser, so a local issue is not mistaken for an outage.
2. Follow the run steps in the project README (the run guide written under US18) on a clean copy cloned from the repository.
3. If the run steps fail, check the most recent commit to `prototype/App.tsx` and revert to the last version that passed testing (the Sprint 4 US16 test results record which one).
4. Tell the team channel and the Product Owner what failed and which version is running.
5. Confirm recovery by scanning the Sprint 4 test URLs (for example TC06 and TC11) and checking the expected results.

### 2.2 The repository is damaged, deleted, or contains something it should not

1. Do not push anything else. Every member has a local clone, so the repository can be rebuilt from the most recent clone.
2. Identify the member with the latest clone (compare `git log` output) and restore the repository from that copy.
3. If sensitive data was committed (a name, contact detail, token, or key), remove it, commit the fix, and revoke or replace any token or key. Deleting the file does not remove it from history, so the revoke step is required.
4. Tell the team lead so the exposure is recorded, and note it in the next sprint review.
5. Confirm recovery by checking that `docs/`, `prototype/` and the test evidence are all present, and that a search for participant names or contact details finds nothing.

### 2.3 A team member is unavailable

1. The team lead reassigns any card the member owned, and the card owner field is updated so each card still has one owner.
2. The new owner reads the card's acceptance criteria and evidence, then the related document in `docs/`. Every deliverable is a file in the repository, so no one holds knowledge that is not written down.
3. If the work cannot be finished this sprint, mark it carried over in the sprint review and say so plainly. Do not mark it done.
4. For the member's standups, the team lead records "unavailable" with the date, so participation records stay accurate.

### 2.4 The live demo fails

1. Switch to running the application locally from the repository using the README steps.
2. If that also fails, use the backup: screenshots of a full scan and the recorded walkthrough.
3. State what happened and which version was shown. Never present a screenshot as a live result.
4. Before the final demo, run the whole demo once on the machine that will be used, from a clean clone.

---

## 3. Current Status From Control Verification

These findings come from checking the controls against `prototype/App.tsx` and the Sprint 4 test results (`docs/Testing/Sprint_4_US16_Testing/README.md`).

- **RM7, stored URL history.** The application saves the last five submitted URLs in browser storage under `phishfinder_history`, as typed, with no masking. This conflicts with the controls in THREATS.md threats 4 and 6 and with ASVS row 8.2.2 in DATA_PROTECTION.md. Resolution is either to store only the hostname or remove the history, or to change the documented controls to say a local-only history exists. Status: open.
- **RM2, weak signals.** TC13 (several weak indicators) scores 25 and is Suspicious, so a combination rule exists. TC08 (several phishing keywords) scores 10 and stays Low Risk. The team decides whether keyword-only URLs should escalate. Status: open.
- **RM3, known-bad list.** The test notes confirm the list is a demonstration list and that URLhaus is a candidate for evaluation only. Status: accepted for now, to be stated in the limitations statement.
- **RM4, no fetching.** The Sprint 4 notes say submitted destinations are not visited, based on inspection of the code. A runtime check with network monitoring is still recommended. Status: verified by code inspection, runtime check pending.

---

## Review

This plan is reviewed at the end of each sprint. Any trigger that occurs is recorded with the action taken, ratings are updated, and the related entry in `THREATS.md` is changed to match.
