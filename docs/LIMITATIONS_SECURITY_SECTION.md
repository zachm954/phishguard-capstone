## Security and Safety Limitations
 
PhishGuard is a learning tool that estimates the risk of a link from its text. It is not a security product, and it does not guarantee that any link is safe or malicious.
 
**A Low Risk result is not a guarantee of safety.** PhishGuard scores a URL from 12 checks on the URL text alone. A phishing link that does not trigger enough of those checks can still be rated Low Risk, and we have tested cases where several phishing keywords together stayed Low Risk. Users should still verify the sender before clicking.
 
**The known-bad list is a demonstration list.** The known-bad check uses a small local list of reserved test entries. It does not cover real-world threats. A maintained source such as URLhaus has been identified for evaluation but is not integrated.
 
**Links are analyzed as text only.** PhishGuard never opens or fetches a submitted link, so it cannot see the page, follow redirects, or expand shortened links. A shortened link is flagged because its destination is hidden, not because the destination was checked.
 
**Scoring is heuristic.** The check weights and thresholds were chosen by the team and tuned on a small set of test cases. They have not been validated against a large sample of real phishing links, so false positives and false negatives are both possible.
 
**Known security gaps found in our own verification (11/10/2026).** The application stores the last five submitted URLs in the user's browser, which can include query values, and it shows credentials in a submitted URL unmasked. Nothing is sent to a server, but users should not submit links that contain personal information or passwords. Rate limiting, security response headers, and a dependency inventory have not been verified or are not implemented. See DATA_PROTECTION.md and RISK_MANAGEMENT_AND_RECOVERY.md.
 
**Scope.** PhishGuard has no logins, accounts, or server-side storage. The Chrome extension is a stretch goal and is not part of this assessment.
 
