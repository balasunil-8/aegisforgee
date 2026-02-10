# Changelog

All notable changes to AegisForge will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.0.0] - 2024-02-09

### 🎉 Major Release - Complete Platform Rebranding & Enhancement

This major release represents a complete transformation from SecurityForge to AegisForge with significant architectural improvements, expanded vulnerability coverage, and new features.

### Added

#### Core Features
- **Dual-Mode Architecture**: Complete separation of vulnerable (Red Team) and secure (Blue Team) implementations
- **OWASP API Security Top 10 2023**: Full implementation of all 10 API security categories
- **CTF Challenge System**: 18 progressive challenges with scoring and leaderboard (2,700 total points)
- **ML-Based AI Detection**: Machine learning model to detect AI-generated vs human-written code
- **Analytics Dashboard**: Real-time security metrics, vulnerability trends, and attack pattern analysis
- **Leaderboard System**: Competitive scoring with timestamps and user rankings

#### Vulnerability Coverage
- **40+ Vulnerable Endpoints**: Covering all OWASP Web & API categories
- **52+ Secure Endpoints**: Hardened implementations with defense-in-depth
- **New API Vulnerabilities**: BOLA, BFLA, BOPLA, Mass Assignment, SSRF, Security Misconfiguration
- **Enhanced Web Vulnerabilities**: Advanced XSS, CSRF, XXE, deserialization attacks

#### Security Defenses
- **Input Validation Module**: SQL injection, XSS, command injection, path traversal protection
- **Rate Limiting**: Configurable IP-based and user-based rate limiting with Redis
- **Security Headers**: CSP, HSTS, X-Frame-Options, CSRF tokens
- **Access Control**: RBAC, object-level authorization, ownership validation
- **Cryptographic Controls**: Secure password hashing, JWT tokens, encryption utilities

#### Tool Integration
- **Postman Collections**: Complete collections for both modes with 90+ requests
- **OWASP ZAP Integration**: Automated scanning configurations and scripts
- **Burp Suite Support**: Custom extensions and test cases
- **SQLMap Integration**: Pre-configured targets and test scenarios
- **ffuf Support**: Directory fuzzing and API endpoint discovery

#### Documentation
- **Comprehensive Guides**: 25+ documentation files covering all aspects
- **API Documentation**: Complete endpoint reference with examples
- **Tool Integration Guides**: Step-by-step setup for all supported tools
- **Learning Paths**: Structured curriculum from beginner to advanced
- **Video Tutorials**: Integration with practical demonstrations

### Changed

- **Project Renamed**: SecurityForge → AegisForge for better branding and clarity
- **API Structure**: RESTful design with consistent endpoint naming (`/api/vulnerable/`, `/api/secure/`)
- **Database Schema**: Enhanced models with relationships and security metadata
- **Configuration System**: Centralized config with environment-based settings
- **Error Handling**: Improved error messages and security-aware responses
- **Performance**: Optimized database queries and caching strategies

### Enhanced

- **User Authentication**: JWT-based with refresh tokens and role-based access
- **Logging System**: Detailed security event logging with structured formats
- **Testing Framework**: Comprehensive test suite with 70%+ code coverage
- **Docker Support**: Multi-stage builds and production-ready configurations
- **CI/CD Pipeline**: Automated testing and deployment workflows

### Fixed

- **SQL Injection**: Parameterized queries in secure mode
- **XSS Vulnerabilities**: Context-aware output encoding
- **CSRF Protection**: Token validation on all state-changing operations
- **Authentication Bypass**: Proper session management and token validation
- **Path Traversal**: Input validation and sanitization
- **Information Disclosure**: Generic error messages in production

### Security

- **CVE Database**: Updated vulnerability patterns and exploit demonstrations
- **Security Scanning**: Integrated SAST and DAST tools in CI/CD
- **Dependency Updates**: All dependencies updated to latest secure versions
- **Secret Management**: Environment-based configuration, no hardcoded secrets
- **Compliance**: OWASP ASVS Level 2 compliance for secure implementations

---

## [1.5.0] - 2024-01-15

### Added

- **CTF Mode**: Initial implementation of challenge-based learning
- **Analytics**: Basic metrics and reporting functionality
- **Docker Compose**: Simplified deployment with containerization
- **Redis Integration**: Session management and caching
- **API Endpoints**: 30+ vulnerable and secure endpoints

### Changed

- **Database**: Migration from SQLite to PostgreSQL support
- **Frontend**: Enhanced dashboard with better UX
- **Documentation**: Expanded API documentation

### Fixed

- **Session Management**: Secure cookie handling
- **CORS Issues**: Proper CORS configuration for API access
- **Database Connections**: Connection pooling and timeout handling

---

## [1.0.0] - 2023-12-01

### 🎉 Initial Release

### Added

#### Core Platform
- **Flask-based API**: RESTful API with JSON responses
- **SQLite Database**: Lightweight database for development
- **User Authentication**: Basic login and registration
- **Session Management**: Server-side session handling

#### OWASP Web Top 10 Coverage
- **A01: Broken Access Control**: User ID manipulation, path traversal
- **A02: Cryptographic Failures**: Weak encryption, plaintext storage
- **A03: Injection**: SQL injection, command injection, XSS
- **A04: Insecure Design**: Missing rate limiting, weak password policy
- **A05: Security Misconfiguration**: Default credentials, verbose errors
- **A06: Vulnerable Components**: Outdated dependencies
- **A07: Authentication Failures**: Weak passwords, no MFA
- **A08: Integrity Failures**: Missing integrity checks
- **A09: Logging Failures**: Insufficient logging
- **A10: SSRF**: Server-side request forgery

#### Vulnerabilities Implemented
- SQL Injection (Basic)
- Cross-Site Scripting (Reflected, Stored)
- CSRF (No token validation)
- Broken Authentication (Weak passwords)
- Sensitive Data Exposure (Plaintext passwords)
- XML External Entities (XXE)
- Broken Access Control (IDOR)
- Security Misconfiguration (Debug mode)
- Insecure Deserialization (Pickle)
- Insufficient Logging (No audit trail)

#### Security Implementations
- Parameterized SQL queries
- Input sanitization for XSS
- CSRF token validation
- Bcrypt password hashing
- HTTPS enforcement
- Security headers (basic)

#### Documentation
- README with setup instructions
- API endpoint documentation
- Basic usage examples
- Deployment guide

#### Testing
- Manual test cases
- Postman collection (basic)
- Sample exploit scripts

---

## [0.9.0] - 2023-11-01 (Beta)

### Added

- **Initial Project Structure**: Basic Flask application skeleton
- **Database Models**: User, Session, Log models
- **Authentication**: Login and registration endpoints
- **Basic Vulnerabilities**: SQL injection, XSS demonstrations
- **Test Environment**: Development server configuration

### Known Issues

- Limited vulnerability coverage
- No CTF challenges
- Basic documentation
- SQLite only (no PostgreSQL)
- No tool integration
- Missing security headers

---

## Version Comparison Summary

| Feature | v1.0 | v1.5 | v2.0 |
|---------|------|------|------|
| **OWASP Web Top 10** | ✅ 100% | ✅ 100% | ✅ 100% |
| **OWASP API Top 10** | ❌ 0% | ⚠️ 30% | ✅ 100% |
| **Vulnerable Endpoints** | 15 | 30 | 40+ |
| **Secure Endpoints** | 10 | 25 | 52+ |
| **CTF Challenges** | ❌ | ⚠️ 5 | ✅ 18 |
| **ML Detection** | ❌ | ❌ | ✅ |
| **Analytics Dashboard** | ❌ | ⚠️ Basic | ✅ Advanced |
| **Tool Integration** | ⚠️ Postman | ⚠️ Postman + ZAP | ✅ All Tools |
| **Docker Support** | ❌ | ✅ | ✅ Enhanced |
| **Documentation** | ⚠️ Basic | ⚠️ Good | ✅ Comprehensive |

---

## Migration Guides

### Upgrading from v1.5 to v2.0

1. **Update Dependencies**:
```bash
pip install -r requirements.txt --upgrade
```

2. **Database Migration**:
```bash
# Backup existing database
cp instance/aegisforge.db instance/aegisforge.db.backup

# Run migration script
python scripts/migrate_v1_to_v2.py
```

3. **Configuration Updates**:
```bash
# Update .env file with new variables
cp .env.example .env.new
# Merge your settings into .env.new
```

4. **API Endpoint Changes**:
- `/vulnerable/*` → `/api/vulnerable/*`
- `/secure/*` → `/api/secure/*`
- Update all API client configurations

### Upgrading from v1.0 to v2.0

Due to significant architectural changes, a clean installation is recommended:

1. Export existing user data (if needed)
2. Perform fresh installation of v2.0
3. Import user data using migration script
4. Update all tool configurations

---

## Deprecation Notices

### Deprecated in v2.0 (To be removed in v3.0)

- **Legacy API Endpoints**: Old non-prefixed endpoints (`/vulnerable/` without `/api/`)
- **SQLite**: Will require PostgreSQL in v3.0
- **Python 3.7**: Minimum version will be Python 3.9 in v3.0

---

## Upcoming Features (v2.1 - Planned)

- **GraphQL API**: Alternative API interface
- **WebSocket Support**: Real-time vulnerability notifications
- **Mobile App**: iOS and Android companion apps
- **Advanced Analytics**: Predictive threat modeling
- **Cloud Deployment**: AWS/Azure one-click deployment
- **Kubernetes Support**: Helm charts for K8s deployment
- **More CTF Challenges**: 30+ total challenges
- **Video Integration**: Embedded tutorial videos

---

## Contributors

Special thanks to all contributors who made AegisForge possible:

- **Core Team**: Architecture, implementation, and documentation
- **Security Researchers**: Vulnerability validation and exploit development
- **Community Contributors**: Bug reports, feature requests, and improvements

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to contribute.

---

## Links

- **Repository**: https://github.com/balasunil-8/aegisforgee
- **Documentation**: See docs/ directory
- **Issue Tracker**: https://github.com/balasunil-8/aegisforgee/issues
- **Security Policy**: [SECURITY.md](SECURITY.md)
- **License**: [MIT License](LICENSE)

---

[2.0.0]: https://github.com/balasunil-8/aegisforgee/releases/tag/v2.0.0
[1.5.0]: https://github.com/balasunil-8/aegisforgee/releases/tag/v1.5.0
[1.0.0]: https://github.com/balasunil-8/aegisforgee/releases/tag/v1.0.0
[0.9.0]: https://github.com/balasunil-8/aegisforgee/releases/tag/v0.9.0
