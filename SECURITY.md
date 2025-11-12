# 🔒 Security Hardening Guide

## Overview
This document outlines security best practices and hardening measures implemented in the BBLAM PHP Laravel project.

## 🛡️ Implemented Security Measures

### 1. **Security Headers**
All HTTP responses include security headers via `SecurityHeadersMiddleware`:

- **X-Frame-Options**: `DENY` - Prevents clickjacking
- **X-Content-Type-Options**: `nosniff` - Prevents MIME sniffing
- **X-XSS-Protection**: `1; mode=block` - Enables XSS filter
- **Strict-Transport-Security**: HSTS for HTTPS-only
- **Content-Security-Policy**: Restricts resource loading
- **Referrer-Policy**: Controls referrer information
- **Permissions-Policy**: Disables unnecessary browser features

### 2. **Rate Limiting**
Custom `RateLimitMiddleware` implements:

- **Per-IP limiting**: Default 60 requests/minute
- **Per-User limiting**: Authenticated users tracked separately
- **Endpoint-specific limits**: Login (5/min), API (100/min)
- **Response headers**: `X-RateLimit-Limit`, `X-RateLimit-Remaining`
- **HTTP 429**: Too Many Requests with `Retry-After`

### 3. **Authentication & Authorization**

#### JWT Security:
- **HS256 algorithm**: Symmetric signing
- **Secret rotation**: Change `JWT_SECRET` regularly
- **Token expiration**: 60 minutes default
- **Refresh tokens**: 14 days TTL
- **Bearer token validation**: Required for protected endpoints

#### Password Security:
- **SHA256 + Salt**: Password hashing (for SQL Server compatibility)
- **Random salt**: 32-byte random salt per user
- **Bcrypt rounds**: 12 rounds (configurable)
- **Password validation**: Minimum 6 characters (should be 8+ in production)

### 4. **Input Validation**
- **Laravel Validation**: All inputs validated before processing
- **SQL Injection Prevention**: PDO prepared statements
- **XSS Prevention**: Auto-escaping in Blade templates
- **CSRF Protection**: Laravel CSRF tokens (disable for API-only)

### 5. **CORS Configuration**
```php
// config/cors.php
'allowed_origins' => env('CORS_ALLOWED_ORIGINS', '*'),
'allowed_methods' => ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
'allowed_headers' => ['Content-Type', 'Authorization', 'X-Requested-With'],
'supports_credentials' => true,
```

### 6. **Docker Security**

#### Non-Root User (Recommended):
```dockerfile
# Add to Dockerfile
RUN groupadd -g 1000 appuser && useradd -u 1000 -g appuser -s /bin/sh appuser
USER appuser
```

#### Read-Only Filesystem:
```yaml
# docker-compose.yml
services:
  app:
    read_only: true
    tmpfs:
      - /tmp
      - /var/www/html/storage/framework/cache
```

#### Security Scanning:
```bash
# Scan image for vulnerabilities
docker scan bblam-php-app:latest

# Trivy scan
trivy image bblam-php-app:latest
```

### 7. **Kubernetes Security**

#### Pod Security:
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  fsGroup: 1000
  capabilities:
    drop:
      - ALL
  readOnlyRootFilesystem: true
```

#### Network Policies:
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: bblam-app-netpol
spec:
  podSelector:
    matchLabels:
      app: bblam-php-app
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: nginx
    ports:
    - protocol: TCP
      port: 9000
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: sqlserver
    ports:
    - protocol: TCP
      port: 1433
```

#### Secrets Management:
- **Kubernetes Secrets**: Base64-encoded (encrypted at rest with EncryptionConfiguration)
- **External Secrets**: Use Sealed Secrets or Vault for production
- **Environment separation**: Different secrets per namespace

### 8. **Database Security**

#### SQL Server:
- **Strong password**: Min 8 chars, uppercase, lowercase, numbers, symbols
- **Encrypted connections**: Use TrustServerCertificate=no in production
- **Limited permissions**: App user should NOT be `sa`
- **Connection pooling**: Prevent connection exhaustion
- **Prepared statements**: Prevent SQL injection

#### Example Production Connection:
```env
DB_CONNECTION=sqlsrv
DB_HOST=prod-sqlserver.database.windows.net
DB_PORT=1433
DB_DATABASE=LOGIN_TEST_PROD
DB_USERNAME=app_user
DB_PASSWORD=YourStrongP@ssw0rd!2024
DB_ENCRYPT=yes
DB_TRUST_SERVER_CERTIFICATE=no
```

### 9. **Logging & Monitoring**

#### Security Events to Log:
- Failed login attempts
- JWT validation failures
- Rate limit violations
- Unauthorized access attempts
- Input validation errors
- Exceptions and errors

#### Recommended Stack:
```yaml
# Loki for log aggregation
# Prometheus for metrics
# Grafana for visualization
# AlertManager for notifications
```

### 10. **SSL/TLS Configuration**

#### Nginx SSL (Production):
```nginx
server {
    listen 443 ssl http2;
    server_name api.bblam.com;
    
    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
}
```

---

## 🚨 Security Checklist (Production)

### Before Deployment:
- [ ] Change all default passwords
- [ ] Generate new `APP_KEY` (`php artisan key:generate`)
- [ ] Generate secure `JWT_SECRET` (256-bit random key)
- [ ] Set `APP_DEBUG=false`
- [ ] Set `APP_ENV=production`
- [ ] Configure CORS allowed origins (no wildcard `*`)
- [ ] Enable HTTPS/SSL certificates
- [ ] Review and restrict file permissions
- [ ] Remove development dependencies
- [ ] Enable security headers middleware
- [ ] Configure rate limiting
- [ ] Set up log monitoring
- [ ] Enable SQL Server encrypted connections
- [ ] Configure firewall rules
- [ ] Set up automated backups
- [ ] Implement intrusion detection
- [ ] Configure security scanning (Trivy, Snyk)
- [ ] Review Kubernetes RBAC policies
- [ ] Enable Pod Security Policies/Standards
- [ ] Configure Network Policies
- [ ] Set resource limits (CPU, Memory)
- [ ] Enable audit logging

### Regular Maintenance:
- [ ] Update dependencies monthly (`composer update`)
- [ ] Rotate secrets quarterly
- [ ] Review access logs weekly
- [ ] Security audit quarterly
- [ ] Penetration testing annually
- [ ] Vulnerability scanning (automated)
- [ ] Update Docker base images
- [ ] Review and update WAF rules
- [ ] Backup testing
- [ ] Disaster recovery drills

---

## 📋 Common Vulnerabilities & Mitigations

| Vulnerability | Mitigation |
|---------------|------------|
| SQL Injection | PDO prepared statements, input validation |
| XSS | Auto-escaping, CSP headers, input sanitization |
| CSRF | Laravel CSRF tokens (disable for API-only) |
| Clickjacking | X-Frame-Options: DENY |
| Man-in-the-Middle | HTTPS/SSL, HSTS header |
| Brute Force | Rate limiting, account lockout |
| Session Hijacking | Secure cookies, HTTP-only, SameSite=strict |
| Insecure Dependencies | Regular updates, composer audit |
| Information Disclosure | Remove debug info, generic error messages |
| Insufficient Logging | Centralized logging, security event tracking |

---

## 🔧 Security Tools

### Development:
```bash
# PHP Security Checker
composer require --dev enlightn/security-checker
php artisan security-check

# OWASP Dependency Check
composer audit

# Static Analysis
composer require --dev phpstan/phpstan
vendor/bin/phpstan analyze

# Code Sniffer
composer require --dev squizlabs/php_codesniffer
vendor/bin/phpcs --standard=PSR12 app/
```

### Production:
```bash
# Trivy (Container scanning)
trivy image bblam-php-app:latest

# Snyk (Dependency scanning)
snyk test

# OWASP ZAP (Penetration testing)
docker run -t owasp/zap2docker-stable zap-baseline.py -t http://api.bblam.com
```

---

## 📞 Security Incident Response

1. **Detection**: Monitor logs and alerts
2. **Containment**: Isolate affected systems
3. **Investigation**: Review logs, identify root cause
4. **Eradication**: Remove malicious code, patch vulnerabilities
5. **Recovery**: Restore from clean backups
6. **Post-Incident**: Document lessons learned, update procedures

**Security Contact**: security@bblam.com

---

## 📚 References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Laravel Security Best Practices](https://laravel.com/docs/10.x/security)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [Kubernetes Security](https://kubernetes.io/docs/concepts/security/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

---

**Last Updated**: November 12, 2025  
**Version**: 1.0.0
