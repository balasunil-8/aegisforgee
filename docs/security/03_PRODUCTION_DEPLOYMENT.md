# Production Deployment Guide

## ⚠️ CRITICAL WARNING

**AegisForge is an EDUCATIONAL platform, NOT designed for production use!**

This guide is provided for completeness, but we **strongly discourage** production deployment.

If you must deploy, follow this guide carefully and understand the risks.

---

## 🎯 Prerequisites

Before considering production deployment:

- [ ] Completed security training
- [ ] Understand all vulnerabilities in Red Team code
- [ ] Read all security documentation
- [ ] Have approval from security team
- [ ] Have legal authorization
- [ ] Understand compliance requirements (GDPR, PCI-DSS, etc.)

---

## 🔐 Production Deployment Checklist

### Phase 1: Code Preparation

- [ ] **Disable ALL Red Team endpoints**
  - Remove Red Team imports
  - Comment out Red Team registrations
  - Verify no vulnerable code paths exist

- [ ] **Enable ONLY Blue Team endpoints**
  - Verify all security controls active
  - Test authorization checks
  - Validate input validation
  - Confirm CSRF protection

- [ ] **Remove test data**
  - Delete seed_data.py imports
  - Remove hardcoded credentials
  - Clear test databases

- [ ] **Update dependencies**
  - Run `pip list --outdated`
  - Update to latest secure versions
  - Review security advisories

### Phase 2: Environment Configuration

- [ ] **Generate production secrets**
  ```bash
  # Flask secret key
  python -c "import secrets; print(secrets.token_hex(32))"
  
  # Database password
  python -c "import secrets; print(secrets.token_urlsafe(32))"
  ```

- [ ] **Configure production environment variables**
  ```bash
  FLASK_ENV=production
  FLASK_DEBUG=False
  FLASK_SECRET_KEY=<strong-random-value>
  DATABASE_URL=postgresql://user:pass@host:5432/db
  SESSION_COOKIE_SECURE=True
  SESSION_COOKIE_SAMESITE=Strict
  RATE_LIMIT_ENABLED=True
  ```

- [ ] **Set up production database**
  - Use PostgreSQL (not SQLite)
  - Enable SSL/TLS connections
  - Configure regular backups
  - Set up read replicas if needed

### Phase 3: Security Hardening

- [ ] **Enable HTTPS**
  - Obtain SSL/TLS certificates (Let's Encrypt recommended)
  - Configure web server for HTTPS
  - Redirect HTTP to HTTPS
  - Enable HSTS headers

- [ ] **Implement rate limiting**
  - Set up Redis for rate limiting
  - Configure per-endpoint limits
  - Add IP-based throttling
  - Monitor for abuse

- [ ] **Add Web Application Firewall (WAF)**
  - Deploy ModSecurity or cloud WAF
  - Configure OWASP Core Rule Set
  - Enable DDoS protection
  - Set up IP whitelisting/blacklisting

- [ ] **Security headers**
  ```python
  # Add to application
  @app.after_request
  def add_security_headers(response):
      response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
      response.headers['X-Content-Type-Options'] = 'nosniff'
      response.headers['X-Frame-Options'] = 'DENY'
      response.headers['X-XSS-Protection'] = '1; mode=block'
      response.headers['Content-Security-Policy'] = "default-src 'self'"
      return response
  ```

- [ ] **Input validation**
  - Validate all user input
  - Sanitize HTML content
  - Implement size limits
  - Use whitelists (not blacklists)

### Phase 4: Monitoring & Logging

- [ ] **Set up logging**
  - Configure structured logging
  - Log to centralized service (ELK, Splunk, etc.)
  - Never log sensitive data
  - Set up log retention policies

- [ ] **Enable monitoring**
  - Application performance monitoring (APM)
  - Error tracking (Sentry, Rollbar, etc.)
  - Security monitoring (SIEM)
  - Uptime monitoring

- [ ] **Set up alerts**
  - Failed login attempts
  - Rate limit violations
  - Unusual traffic patterns
  - Application errors

### Phase 5: Deployment

- [ ] **Use containers**
  - Docker with minimal base image
  - Non-root user
  - Read-only file system where possible
  - Security scanning (Trivy, Snyk, etc.)

- [ ] **Infrastructure as Code**
  - Use Terraform/CloudFormation
  - Version control infrastructure
  - Implement least privilege
  - Enable audit logging

- [ ] **Load balancing**
  - Multiple application instances
  - Health checks
  - Automatic failover
  - Session persistence

---

## 🚫 What NOT to Deploy

### Never Deploy These Components:

1. **Red Team Endpoints**
   - `securebank_red_api.py`
   - `a05_misconfiguration_red.py`
   - Any endpoint with `/api/red/`

2. **Test Data**
   - `seed_data.py`
   - Test credentials
   - Sample transactions

3. **Debug Tools**
   - Flask debug mode
   - Verbose error messages
   - SQL query logging

4. **Development Features**
   - CORS wildcard (`*`)
   - Permissive firewalls
   - Weak secret keys

---

## 🏗️ Recommended Architecture

### Minimal Production Architecture

```
Internet
  ↓
WAF / CDN (Cloudflare, AWS WAF)
  ↓
Load Balancer (AWS ALB, Nginx)
  ↓
Application Servers (Blue Team only)
  ↓
Database (PostgreSQL with SSL)
  ↓
Redis (Session storage, rate limiting)
```

### Additional Components

- **Secret Management:** AWS Secrets Manager, HashiCorp Vault
- **Monitoring:** Datadog, New Relic, Prometheus
- **Logging:** ELK Stack, CloudWatch
- **Backups:** Automated daily backups with encryption

---

## 📝 Configuration Examples

### Production docker-compose.yml
```yaml
version: '3.8'

services:
  aegisforge:
    image: aegisforge:production
    restart: always
    environment:
      - FLASK_ENV=production
      - FLASK_DEBUG=False
    env_file:
      - .env.production
    networks:
      - aegisforge-network
    depends_on:
      - postgres
      - redis
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  postgres:
    image: postgres:15-alpine
    restart: always
    environment:
      - POSTGRES_DB=aegisforge
      - POSTGRES_PASSWORD_FILE=/run/secrets/db_password
    volumes:
      - postgres-data:/var/lib/postgresql/data
    secrets:
      - db_password
    networks:
      - aegisforge-network

  redis:
    image: redis:7-alpine
    restart: always
    command: redis-server --requirepass $(cat /run/secrets/redis_password)
    secrets:
      - redis_password
    networks:
      - aegisforge-network

networks:
  aegisforge-network:
    driver: bridge

volumes:
  postgres-data:

secrets:
  db_password:
    file: ./secrets/db_password.txt
  redis_password:
    file: ./secrets/redis_password.txt
```

---

## 🧪 Pre-Deployment Testing

### Security Testing Checklist

- [ ] Run OWASP ZAP scan
- [ ] Run Burp Suite scan
- [ ] Penetration testing
- [ ] Code review
- [ ] Dependency scanning
- [ ] Container scanning

### Performance Testing

- [ ] Load testing
- [ ] Stress testing
- [ ] Spike testing
- [ ] Endurance testing

---

## 📋 Post-Deployment

### Immediate Actions

1. **Verify security controls**
   - Test rate limiting
   - Verify HTTPS
   - Check security headers
   - Test authentication

2. **Monitor logs**
   - Watch for errors
   - Check traffic patterns
   - Monitor performance

3. **Set up backups**
   - Verify backup process
   - Test restoration
   - Document procedures

### Ongoing Maintenance

- Regular security updates
- Monthly security reviews
- Quarterly penetration tests
- Annual security audits

---

## ⚠️ Final Warning

**We STRONGLY recommend keeping AegisForge as a local learning environment only!**

If you deploy to production:
- You assume all risks
- You are responsible for security
- You must comply with all regulations
- You should have professional security review

**Consider using established, production-ready frameworks instead!**

---

**Last Updated:** February 2026
