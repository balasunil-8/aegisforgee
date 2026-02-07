# Real-World Security Incidents

Real bug bounty reports and CVEs related to SecureBank vulnerabilities.

## SQL Injection Cases

### Capital One Data Breach (2019)
- **Impact**: 100+ million customer records exposed
- **CVE**: N/A (SSRF leading to data access)
- **Similar to**: SecureBank login vulnerability
- **Lesson**: Always use parameterized queries

### British Airways Breach (2018)
- **Impact**: £20 million GDPR fine
- **Technique**: JavaScript injection + data theft
- **Loss**: 400,000+ customer payment cards
- **Lesson**: Input validation and output encoding critical

## IDOR Vulnerabilities

### USPS "Informed Visibility" (2018)
- **Impact**: 60 million user accounts exposed
- **Issue**: IDOR in API allowed any authenticated user to access others' data
- **Similar to**: SecureBank account access vulnerability
- **Bounty**: $0 (government system)

### Facebook Graph API IDOR
- **Bounty**: $10,000+
- **Issue**: Could access private photos via predictable IDs
- **Fix**: Authorization checks on every request

## Race Condition Vulnerabilities

### Cryptocurrency Exchange Race Condition
- **Loss**: $31 million in Bitcoin
- **Issue**: Withdrawal requests not properly locked
- **Similar to**: SecureBank transfer vulnerability
- **Lesson**: Use database transactions and locks

### E-commerce Coupon Race Condition
- **Bounty**: $5,000
- **Issue**: Same coupon used multiple times in parallel
- **Fix**: Atomic operations with row locking

## XSS Vulnerabilities

### Twitter XSS Worm (2010)
- **Impact**: Millions of users affected in minutes
- **Technique**: Self-propagating XSS in tweets
- **Similar to**: SecureBank transaction notes XSS
- **Lesson**: Always encode output, use CSP

### PayPal Stored XSS
- **Bounty**: $10,000
- **Location**: Transaction description field
- **Impact**: Could steal session tokens
- **Fix**: HTML entity encoding

## Mass Assignment Vulnerabilities

### GitHub Mass Assignment (2012)
- **Impact**: Unauthorized repository access
- **Issue**: Could set admin privileges via POST parameters
- **Similar to**: SecureBank profile update
- **Fix**: Whitelist allowed fields

### Ruby on Rails Apps
- **Common issue**: params.permit(:all) allowing role escalation
- **Lesson**: Always use field whitelisting

## CSRF Vulnerabilities

### Netflix CSRF (2006)
- **Impact**: Could change account settings
- **Issue**: No CSRF token on sensitive actions
- **Similar to**: SecureBank settings page
- **Fix**: Synchronizer token pattern

### Router CSRF Attacks
- **Impact**: DNS hijacking via CSRF
- **Technique**: Malicious page changes router DNS
- **Lesson**: CSRF tokens even for authenticated requests

## Statistics

- **SQL Injection**: #3 in OWASP Top 10 2021
- **IDOR**: #1 in OWASP Top 10 2021 (Broken Access Control)
- **XSS**: #3 in OWASP Top 10 2021
- **Average Bug Bounty**: $1,000-$25,000 for critical findings

## Lessons for Developers

1. **Defense in Depth**: Multiple security layers
2. **Input Validation**: Never trust user input
3. **Output Encoding**: Prevent injection attacks
4. **Authorization**: Check on every request
5. **Atomic Operations**: Use transactions for critical operations
6. **CSRF Protection**: For all state-changing operations
7. **Regular Testing**: Automated and manual security testing
8. **Stay Updated**: Follow security advisories

## Resources

- OWASP Top 10: https://owasp.org/www-project-top-ten/
- CVE Database: https://cve.mitre.org/
- Bug Bounty Platforms: HackerOne, Bugcrowd, Synack
- Security News: The Hacker News, Krebs on Security
