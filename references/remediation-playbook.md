# Remediation Playbook

Standard fix guidance per vulnerability class. Use this to give consistent, actionable remediation advice.

---

## Injection

### SQL Injection
**Fix**: Always use parameterized queries / prepared statements. Never concatenate user input into SQL strings.
```python
# Python
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# Node.js
db.query('SELECT * FROM users WHERE id = ?', [userId])

# Java
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
ps.setInt(1, userId);
```
**Additional**: Enable ORM-level query validation. Add WAF rules as defense-in-depth.

### Command Injection
**Fix**: Never use `shell=True` or string concatenation with OS commands. Use list-based subprocess calls or avoid shell execution entirely.
```python
# Python
subprocess.run(["ping", "-c", "1", host], capture_output=True)
```

### XSS
**Fix**: Use template engine auto-escaping. Sanitize user input server-side. Apply CSP headers.
```html
Content-Security-Policy: default-src 'self'; script-src 'self'
```

---

## Broken Access Control / IDOR

**Fix**: Always verify resource ownership server-side before returning data. Never rely solely on client-provided IDs.
```python
doc = Document.query.filter_by(id=doc_id, owner_id=current_user.id).first_or_404()
```
**Additional**: Implement centralized authorization middleware. Log all access control failures.

---

## Cryptographic Failures

### Weak Password Hashing
**Fix**: Use bcrypt, Argon2, or scrypt. Never use MD5/SHA1 for passwords.
```python
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
```

### Hardcoded Secrets
**Fix**: Move to environment variables immediately. Rotate any exposed credentials.
```python
# Use environment variables
import os
SECRET_KEY = os.environ['SECRET_KEY']
API_KEY = os.environ['API_KEY']
```
**Additional**: Add `.env` to `.gitignore`. Use a secrets manager (HashiCorp Vault, AWS Secrets Manager) for production. Scan git history for leaked secrets (`git-secrets`, `truffleHog`).

### Weak Algorithms
**Fix**: 
- Hashing: Use SHA-256 minimum (SHA-3 preferred for new code)
- Symmetric encryption: AES-256-GCM
- Asymmetric: RSA-2048+ or ECDSA P-256+
- TLS: Require TLS 1.2 minimum, prefer TLS 1.3

---

## Authentication Failures

### Insecure JWT
**Fix**: Always verify signature. Use strong secret (256-bit+) or asymmetric keys. Set expiry.
```python
payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
# Never: algorithms=['none'] or verify_signature=False
```

### Missing Rate Limiting
**Fix**: Apply rate limiting to login, password reset, OTP endpoints.
```python
# Flask-Limiter
@limiter.limit("5 per minute")
@app.route('/login', methods=['POST'])
def login(): ...
```

### Brute Force Protection
**Fix**: Implement account lockout after N failures (5–10). Add exponential backoff. Log and alert on repeated failures.

---

## Security Misconfiguration

### Debug Mode in Production
**Fix**: Disable debug mode via environment config. Use separate config files per environment.
```python
DEBUG = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
```

### Missing Security Headers
**Fix**: Add the following headers to all responses:
```
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: default-src 'self'
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=()
```

### Permissive CORS
**Fix**: Allowlist specific origins. Never use `*` on authenticated APIs.
```python
CORS(app, origins=["https://app.yourdomain.com"])
```

---

## Vulnerable Dependencies

**Fix procedure**:
1. Run `pip audit`, `npm audit`, or `mvn dependency-check:check`
2. Update to patched version
3. Run tests after update
4. If update is not possible, assess if vulnerable code path is reachable and apply mitigating controls

**For transitive dependencies**: Explicitly pin the vulnerable transitive package to a safe version in your manifest.

---

## Deserialization

**Fix**: Never deserialize untrusted data with `pickle`, `yaml.load()`, Java's `ObjectInputStream` without type filtering, or XStream without allowlists.
```python
# Python
yaml.safe_load(data)     # not yaml.load()
# Avoid pickle on user data entirely
```
```java
// Java – use type filtering
ObjectInputStream ois = new ValidatingObjectInputStream(inputStream);
ois.accept(SafeClass.class);
```

---

## SSRF

**Fix**: Validate URLs against an allowlist of domains/IPs before making server-side requests.
```python
from urllib.parse import urlparse

ALLOWED_HOSTS = {'api.trustedpartner.com', 'data.internal-safe.com'}

def safe_fetch(url):
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("URL not in allowlist")
    return requests.get(url, timeout=5)
```
**Additional**: Block requests to `169.254.169.254` (cloud metadata). Use network-level egress controls.

---

## Logging Issues

### Sensitive Data in Logs
**Fix**: Remove credentials, tokens, PII from log statements. Use structured logging with field allowlists.
```python
# Never log
logger.info(f"Login: user={username}, password={password}")

# OK
logger.info("Login attempt", extra={"user_id": user_id, "ip": ip_address})
```
