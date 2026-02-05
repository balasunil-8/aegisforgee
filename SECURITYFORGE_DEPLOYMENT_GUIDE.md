# SecurityForge Production Deployment Guide

## 🚀 Quick Start Deployment

### Prerequisites
- Docker & Docker Compose (for local/containerized deployment)
- Python 3.10+ (for direct deployment)
- Git account
- Cloud platform account (Railway, Render, Heroku, or AWS)

---

## 📦 Option 1: Deploy to Railway.app (Recommended - 5 minutes)

### Setup
1. Go to [railway.app](https://railway.app)
2. Create new project → GitHub repo
3. Connect your GitHub account
4. Select `securitgforge` repository

### Configuration
1. Add environment variables:
   ```
   FLASK_ENV=production
   DATABASE_URL=postgresql://...
   SECRET_KEY=[generate random string]
   JWT_SECRET_KEY=[generate random string]
   ```

2. Create `railway.toml` in project root:
   ```toml
   [build]
   builder = "dockerfile"

   [deploy]
   startCommand = "python securityforge_api.py"
   restartPolicyType = "on_failure"
   restartPolicyMaxRetries = 3
   ```

3. Deploy:
   ```bash
   railway up
   ```

### Verify
```bash
curl https://[your-railway-url]/api/health
```

---

## 🐳 Option 2: Deploy with Docker (Self-Hosted)

### Build Docker Image
```bash
docker build -t securityforge:latest -f Dockerfile.production .
```

### Run Container
```bash
docker run -p 5000:5000 \
  -e FLASK_ENV=production \
  -e DATABASE_URL=postgresql://user:pass@db:5432/securityforge \
  securityforge:latest
```

### Docker Compose
```bash
docker-compose -f docker-compose.production.yml up -d
```

Verify:
```bash
docker ps
curl http://localhost:5000/api/health
```

---

## ☁️ Option 3: Deploy to Render.com (Easy Alternative)

### Setup
1. Go to [render.com](https://render.com)
2. Create New → Web Service
3. Connect GitHub repository
4. Configure:
   - **Name**: securityforge
   - **Runtime**: Python 3.11
   - **Build Command**: `pip install -r requirements_securityforge.txt`
   - **Start Command**: `gunicorn -w 4 -b 0.0.0.0:5000 securityforge_api:app`

### Environment Variables
```
FLASK_ENV=production
DATABASE_URL=[from Render Postgres]
SECRET_KEY=[generate]
JWT_SECRET_KEY=[generate]
```

### Deploy
Click "Deploy" - Done! Your app is live.

Verify:
```bash
curl https://[your-render-url]/api/health
```

---

## 🔧 Option 4: AWS Deployment (Advanced)

### Using AWS Elastic Beanstalk

1. **Prepare**:
   ```bash
   eb init -p python-3.11 securityforge
   eb create securityforge-env
   ```

2. **Configure** `requirements_securityforge.txt`:
   ```
   Flask==3.0.0
   Flask-SQLAlchemy==3.1.1
   Flask-JWT-Extended==4.5.3
   psycopg2-binary==2.9.9
   python-dotenv==1.0.0
   gunicorn==21.2.0
   ```

3. **Deploy**:
   ```bash
   eb deploy
   ```

4. **Scale**:
   ```bash
   eb config  # Modify instance type
   ```

---

## 📊 Option 5: Heroku Deployment (Classic)

### Setup Heroku
```bash
heroku login
heroku create securityforge
```

### Configure
1. Create `Procfile`:
   ```
   web: gunicorn -w 4 securityforge_api:app
   ```

2. Add PostgreSQL addon:
   ```bash
   heroku addons:create heroku-postgresql:mini
   ```

3. Set environment variables:
   ```bash
   heroku config:set FLASK_ENV=production
   heroku config:set SECRET_KEY=[generate]
   ```

### Deploy
```bash
git push heroku main
```

Verify:
```bash
heroku open
curl [your-heroku-url]/api/health
```

---

## 🔐 Production Configuration Checklist

### Security Settings
- [ ] Set `DEBUG=False`
- [ ] Use strong `SECRET_KEY` (40+ characters)
- [ ] Use strong `JWT_SECRET_KEY`
- [ ] Enable HTTPS/TLS
- [ ] Set secure session cookies
- [ ] Enable CORS only for trusted origins
- [ ] Use environment variables (never hardcode secrets)
- [ ] Enable rate limiting
- [ ] Set up security headers (HSTS, CSP, X-Frame-Options)

### Database Settings
- [ ] Use PostgreSQL in production (not SQLite)
- [ ] Enable automated backups
- [ ] Use connection pooling
- [ ] Set READ_ONLY replicas for safety
- [ ] Enable database encryption
- [ ] Regular backup testing

### Monitoring & Logging  
- [ ] Set up error tracking (Sentry)
- [ ] Configure logging (CloudWatch, ELK)
- [ ] Monitor API usage
- [ ] Set up performance monitoring
- [ ] Create backup procedures
- [ ] Plan disaster recovery

### API Security
- [ ] Rate limit endpoints
- [ ] Implement request validation
- [ ] Add request/response logging
- [ ] Monitor for abuse patterns
- [ ] Document all endpoints
- [ ] Regular security audits

---

## 🚨 Production Environment Variables

```bash
# Required
FLASK_ENV=production
SECRET_KEY=<generate-40-char-random>
JWT_SECRET_KEY=<generate-40-char-random>
DATABASE_URL=postgresql://user:pass@host:5432/securityforge

# Optional
CORS_ORIGINS=https://yourdomain.com
LOG_LEVEL=INFO
SENTRY_DSN=https://...@sentry.io/...
REDIS_URL=redis://...
```

---

## 📝 Deployment Verification Checklist

After deploying, verify with these commands:

```bash
# 1. Health Check
curl https://[YOUR_URL]/api/health
# Expected: {"ok": true, "service": "SecurityForge Pro API", "version": "v2.0"}

# 2. Security Config (should NOT be visible in production)
curl https://[YOUR_URL]/api/config
# Expected: 403 Forbidden or missing

# 3. Vulnerable Endpoints (for testing)
curl "https://[YOUR_URL]/api/search?q=test"
# Expected: 200 OK with results

# 4. HTTPS/TLS Check
curl -I https://[YOUR_URL]/api/health | grep HSTS
# Expected: HSTS header present

# 5. CORS Check
curl -H "Origin: https://example.com" -H "Access-Control-Request-Method: GET" https://[YOUR_URL]/api/health
# Expected: Proper CORS headers

# 6. Performance
curl -w "Time: %{time_total}s\n" -o /dev/null -s https://[YOUR_URL]/api/health
# Expected: <200ms response time
```

---

## 🔄 CI/CD Pipeline Setup (GitHub Actions)

Create `.github/workflows/deploy.yml`:

```yaml
name: Deploy to Production

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Run tests
        run: |
          pip install -r requirements_securityforge.txt
          python -m pytest tests/
      
      - name: Deploy to Railway
        if: success()
        run: |
          npm install -g @railway/cli
          railway up
        env:
          RAILWAY_TOKEN: ${{ secrets.RAILWAY_TOKEN }}
```

---

## 📈 Scaling Considerations

### Horizontal Scaling
- Use load balancer (AWS ELB, Nginx, HAProxy)
- Deploy multiple API instances
- Use session store (Redis) instead of memory
- Database connection pooling

### Caching
- Add Redis for session storage
- Cache API responses with CDN
- Cache static assets (CDN)
- Browser caching headers

### Database Optimization
- Add indexes on frequently queried fields
- Use read replicas for analytics
- Archive old logs
- Regular VACUUM/ANALYZE

---

## 🆘 Troubleshooting

### Port Already in Use
```bash
# Find process using port 5000
lsof -i :5000
# Kill process
kill -9 <PID>
```

### Module Import Errors
```bash
# Verify requirements installed
pip install -r requirements_securityforge.txt
pip list | grep -i flask
```

### Database Connection Issues
```bash
# Test database connection
psql $DATABASE_URL
# Verify credentials and URL format
```

### Deployment Logs
```bash
# Railway
railway logs

# Render
# Go to Render dashboard → Logs

# Heroku
heroku logs --tail
```

---

## 📊 Post-Deployment Monitoring

Monitor these metrics:
- **API Response Time**: Target <200ms p95
- **Error Rate**: Target <0.5% 
- **Uptime**: Target 99.9%
- **Database Connections**: Monitor pool usage
- **Disk Space**: Prevent full disks
- **Memory Usage**: Watch for leaks

Set up alerts for:
- High error rate (>1%)
- Response time >1s
- Services down (uptime <99%)
- Database full (>80%)
- CPU >80% for 5+ minutes

---

## 🎯 Success Metrics

✅ **GREEN** = Deployment Ready:
- API responds in <200ms
- All 9 vulnerable endpoints accessible
- Health endpoint returns 200 OK
- HTTPS working with valid certificate
- Database connected and synced
- No errors in logs
- Monitoring configured

---

## 📚 Additional Resources

- [Railway.app Docs](https://docs.railway.app)
- [Render.com Docs](https://render.com/docs)
- [Heroku Docs](https://www.heroku.com/platform)
- [Docker Best Practices](https://docs.docker.com/develop/dev-best-practices/)
- [Flask Production Checklist](https://flask.palletsprojects.com/en/2.3.x/deploying/)

---

**Status**: 🟢 Ready for Production Deployment
**Last Update**: 2025-01-06  
**Project**: SecurityForge v2.0
