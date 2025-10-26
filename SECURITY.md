# Security Policy

## Reporting Security Vulnerabilities

The security of WAF Presence Checker is important to us. If you discover a security vulnerability, we appreciate your help in disclosing it to us responsibly.

### How to Report

**Please DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, please report security vulnerabilities through one of the following methods:

1. **Email:** Send details to email (will be here)
2. **Private Security Advisory:** Use GitHub's private vulnerability reporting feature
3. **Encrypted Communication:** If you prefer, request a PGP key for encrypted communication

### What to Include

Please include the following information in your report:

- **Description** of the vulnerability
- **Steps to reproduce** the issue
- **Potential impact** of the vulnerability
- **Suggested fix** (if you have one)
- **Your contact information** for follow-up questions
- **Whether you want public acknowledgment** when the issue is fixed

### What to Expect

When you report a vulnerability, you can expect:

1. **Acknowledgment** within 48 hours of your report
2. **Regular updates** on our progress (at least weekly)
3. **Estimated timeline** for a fix or mitigation
4. **Credit** in the security advisory (if you wish)
5. **Notification** when the vulnerability is fixed

### Our Commitment

We commit to:

- Respond promptly to security reports
- Keep you informed of our progress
- Work with you to understand and resolve the issue
- Credit you for your discovery (if you wish)
- Publicly disclose the vulnerability responsibly after a fix is available

## Security Best Practices for Users

### Using This Tool Safely

1. **Authorization First**
   - ALWAYS obtain written authorization before collecting HTTP responses for analysis
   - Ensure you have permission to test the target systems
   - Follow Rules of Engagement (ROE) for your engagement

2. **Data Handling**
   - Be careful with HTTP captures that may contain sensitive data
   - Sanitize captures before sharing (remove auth tokens, session IDs, etc.)
   - Do not commit real capture files to version control
   - Use `.gitignore` to prevent accidental exposure

3. **Offline Operation**
   - This tool is designed to operate completely offline
   - Verify no network connections are made during analysis
   - Use in isolated/airgapped environments when analyzing sensitive captures

4. **Input Validation**
   - Be cautious when analyzing untrusted input files
   - The tool includes basic input validation, but use caution
   - Run analysis in sandboxed environments when processing untrusted data

### Secure Development Practices

If you're contributing to this project:

1. **Code Review**
   - All code changes require review
   - Security-sensitive changes require additional scrutiny
   - Use static analysis tools (mypy, ruff, bandit)

2. **Dependencies**
   - This project minimizes dependencies (uses Python stdlib only)
   - Any new dependencies must be carefully vetted
   - Keep development dependencies up to date

3. **Input Handling**
   - Validate all user inputs
   - Use safe parsing methods
   - Limit resource consumption (file sizes, parsing depth)
   - Prevent injection attacks in parsers

4. **Output Safety**
   - Sanitize outputs to prevent information disclosure
   - Limit error message verbosity in production
   - Avoid exposing internal paths or system information

## Scope

### In Scope

Security issues in the following areas are in scope:

- **Code Execution:** Vulnerabilities allowing arbitrary code execution
- **Denial of Service:** Issues causing excessive resource consumption
- **Information Disclosure:** Unintended exposure of sensitive information
- **Input Validation:** Injection or parsing vulnerabilities
- **Logic Flaws:** Issues in detection logic that could be exploited

### Out of Scope

The following are considered out of scope:

- **Social Engineering:** Issues requiring social engineering
- **Physical Access:** Issues requiring physical access to the system
- **Network Scanning:** The tool is explicitly offline-only
- **Known Limitations:** Documented limitations in detection accuracy
- **Third-party Dependencies:** Issues in Python standard library or OS

## Responsible Disclosure

### Timeline

We follow a coordinated disclosure timeline:

1. **Day 0:** Vulnerability reported
2. **Day 1-2:** Initial acknowledgment
3. **Day 7:** Initial assessment complete
4. **Day 30:** Fix developed and tested (target)
5. **Day 90:** Public disclosure (maximum, may be sooner if fix is ready)

### Exceptions

We may deviate from this timeline if:

- The vulnerability is actively being exploited
- The fix is particularly complex
- Coordinating with other affected parties
- At the reporter's request

## Security Updates

### How We Communicate Security Updates

Security updates will be communicated through:

1. **GitHub Security Advisories**
2. **Release Notes** in CHANGELOG.md
3. **Git Tags** for security releases
4. **README.md** updates (for critical issues)

### Version Support

- **Latest Release:** Fully supported with security updates
- **Previous Minor Version:** Security fixes for critical vulnerabilities
- **Older Versions:** Upgrade recommended, limited support

## Known Security Considerations

### Design Decisions

1. **Offline Only**
   - The tool deliberately does not make network requests
   - This prevents unauthorized scanning/testing
   - Encourages proper authorization and ROE compliance

2. **No Evasion Techniques**
   - The tool focuses on detection, not bypass
   - Does not include WAF evasion capabilities
   - Promotes defensive security use cases

3. **Limited Fingerprints**
   - Fingerprint database is intentionally limited
   - Reduces false certainty and misplaced confidence
   - Encourages multi-source verification

### File Handling

- Input files are limited to reasonable sizes (4KB body excerpts)
- Parsers include safeguards against malformed input
- Temporary files are not created
- All processing happens in memory

### Privacy

- No telemetry or analytics are collected
- No network communication occurs
- All analysis is local
- User data is not transmitted

## Security Hardening Recommendations

For production use:

1. **Run in Restricted Environment**
   ```bash
   # Use virtual environment
   python -m venv venv
   source venv/bin/activate
   pip install -e .
   ```

2. **Limit File Access**
   - Run with minimum required permissions
   - Use read-only mounts for input files
   - Write outputs to controlled directories

3. **Monitor Resource Usage**
   - Set memory limits
   - Set CPU time limits
   - Monitor for unusual behavior

4. **Audit Logs**
   - Enable verbose logging for audit trails
   - Review logs for suspicious activity
   - Maintain immutable log storage

## Security Testing

This project welcomes security testing:

- ✅ Static analysis (SAST)
- ✅ Dependency scanning
- ✅ Fuzzing of input parsers
- ✅ Code review
- ✅ Threat modeling

Please report findings responsibly through the disclosure process above.

## Acknowledgments

We would like to thank the following security researchers (add names as appropriate):

- (List of security researchers who have responsibly disclosed vulnerabilities)

## Questions?

If you have questions about this security policy:

- Open an issue tagged with `security-question`
- Contact the maintainers privately
- Review our Code of Conduct

---

**Thank you for helping keep WAF Presence Checker and its users safe!**
