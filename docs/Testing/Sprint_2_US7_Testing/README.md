# Sprint 2 – US7 Testing

## User Story

US7: As an everyday email user, submit a URL and receive a risk level
based on multiple checks, with plain-language reasons explaining the result.

## Acceptance Criteria

- [x] Single hardcoded check is replaced with the agreed set of checks and scoring rules
- [x] Submitted URL returns a risk level based on multiple detected indicators
- [x] Explanations returned match the specific indicators detected
- [x] Results are consistent with predefined test cases

## Test Results

| Test | URL | Expected Result | Actual Result | Status |
|------|-----|-----------------|---------------|--------|
| TC01 | https://www.youtube.com | Safe | Safe | PASS |
| TC02 | http://example.com | Suspicious | Suspicious | PASS |
| TC03 | https://bit.ly/example | Suspicious | Suspicious | PASS |
| TC04 | http://secure-login.paypa1.com | Phishing | Phishing | PASS |
| TC05 | https://example.xyz | Suspicious | Suspicious | PASS |

## Testing Summary

The PhishGuard URL analyzer was tested against multiple URL scenarios
covering safe, suspicious, and phishing indicators. The application
successfully evaluated multiple indicators, calculated the appropriate
risk level, and displayed explanations corresponding to the detected
indicators.

All predefined test cases produced the expected results.

## Evidence

Screenshots of each test result are included in this folder:

- TC01_Safe_URL.png
- TC02_No_HTTPS.png
- TC03_URL_Shortener.png
- TC04_Phishing_URL.png
- TC05_Suspicious_TLD.png
