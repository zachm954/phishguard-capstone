# Sprint 4 — US16 Testing Results

**Project:** PhishGuard  
**Sprint:** 4  
**User Story:** US16 — Harden URL scoring against false positives and false negatives  
**Owner:** Zachariah Melendez-Martinez  
**Test Date:** October 30, 2026

## Objective

Verify that PhishGuard correctly handles legitimate URLs, multiple weak phishing indicators, malformed URLs, brand impersonation, and configured known-bad entries without automatically visiting submitted destinations.

## Test Results

| Test ID | Test Case | Actual Score | Actual Result | Status |
|---|---|---|---|---|
| TC06 | Google legitimate URL | 0 | Low Risk | Pass |
| TC07 | bit.ly URL shortener | 5 | Low Risk | Pass |
| TC08 | Multiple phishing keywords | 10 | Low Risk | Pass |
| TC09 | Invalid URL format | N/A | URL rejected | Pass |
| TC10 | Invalid port | N/A | URL rejected | Pass |
| TC11 | Configured known-bad URL | 100 | Phishing | Pass |
| TC12 | Fake PayPal hostname | 40 | Phishing | Pass |
| TC13 | Multiple weak indicators | 25 | Suspicious | Pass |

**Supplemental test results:** 8/8 matched expected scores and classifications (100%).

These tests are separate from the team's predefined QA suite and do not establish its overall QA pass rate.

## Findings

- URL shorteners alone do not automatically produce a Suspicious classification.
- Malformed URLs and invalid ports are rejected.
- Multiple weak indicators contribute to the weighted risk score.
- Known-bad demonstration entries produce a score of 100.
- Brand impersonation combined with phishing-related indicators triggers the Phishing classification.

## Known-Bad List Status

The current implementation uses a local demonstration list containing reserved testing entries. A maintained threat-intelligence source must be selected and integrated before production use. URLhaus is a candidate for evaluation, not an active integration.

## Limitations

PhishGuard uses heuristic URL analysis. Low Risk does not guarantee a URL is safe. Submitted destinations are not automatically visited by the analyzer, based on the inspected application code; a separate runtime/network verification is still recommended.

## Evidence

Screenshots for TC06–TC13 are stored alongside this README.
