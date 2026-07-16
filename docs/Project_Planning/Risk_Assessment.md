# Risk Assessment – PhishGuard

## Purpose
This risk assessment identifies potential threats, vulnerabilities, risks, and mitigation strategies associated with the PhishGuard project.

Because PhishGuard is a cybersecurity-focused web application concept, security planning is a critical part of project design.

---

## Risk Rating Scale

### Likelihood
- Low = Unlikely
- Medium = Possible
- High = Likely

### Impact
- Low = Minor disruption
- Medium = Moderate damage
- High = Significant damage

### Risk Rating
Risk ratings are determined based on likelihood and impact.

---

## Risk Assessment Table

| Risk ID | Asset | Threat | Vulnerability | Likelihood | Impact | Risk Rating | Mitigation |
|--------|------|--------|--------------|------------|--------|-------------|------------|
| R1 | User-submitted content | Sensitive data exposure | Users may submit personal or confidential information | Medium | High | High | Warn users not to submit sensitive data, minimize storage, restrict access |
| R2 | Web interface | Cross-site scripting (XSS) | Unsanitized user input | High | High | High | Input sanitization, output escaping, secure rendering |
| R3 | Database / storage | SQL injection | Unsafe query handling | Medium | High | High | Parameterized queries, ORM protections |
| R4 | Admin dashboard | Unauthorized access | Weak authentication controls | Medium | High | High | Role-based access control, secure authentication |
| R5 | URL analysis feature | Unsafe link interaction | Users may click suspicious links | Medium | High | High | Defang URLs, display warnings, prevent direct execution |
| R6 | Detection logic | False negatives | Limited phishing detection coverage | High | Medium | High | Explain limitations, continuously improve rules |
| R7 | Detection logic | False positives | Legitimate content incorrectly flagged | Medium | Medium | Medium | Explain reasoning, improve analysis criteria |
| R8 | Project repository | Secret exposure | Credentials accidentally committed | Medium | High | High | .gitignore, environment variables, secret management |
| R9 | Availability | Spam / abuse | Lack of submission controls | Medium | Medium | Medium | Rate limiting, validation, input size restrictions |
| R10 | Team coordination | Missed deadlines | Poor project communication | Medium | Medium | Medium | Scrum meetings, issue tracking, task ownership |

---

## Highest Priority Risks

### XSS
User-submitted content creates a realistic risk of malicious script injection if not properly sanitized.

Priority mitigation:
- Sanitize all inputs
- Escape rendered outputs
- Validate content before processing

---

### Sensitive Data Exposure
Users may accidentally paste passwords, personal data, or confidential information.

Priority mitigation:
- User warning notices
- Data minimization
- Limited retention policies

---

### False Negatives
The system may fail to detect sophisticated phishing attempts.

Priority mitigation:
- Explain limitations
- Encourage caution
- Avoid claiming guaranteed detection

---

### Repository Secret Exposure
Team members may accidentally commit sensitive credentials.

Priority mitigation:
- Use .gitignore
- Avoid storing secrets in source control
- Use environment variables

---

## Security Design Principles
PhishGuard will follow core security principles including:

- Least privilege
- Input validation
- Secure defaults
- Defense in depth
- Transparency of system limitations
- User safety prioritization

---

## Capstone 1 Note
This assessment supports project planning and architectural decision-making for Capstone 1.

Future technical implementation may require expanded threat modeling and security validation.
