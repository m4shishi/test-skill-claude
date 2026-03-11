# OWASP Top 10 – AppSec Review Reference

## Table of Contents
1. [A01 – Broken Access Control](#a01)
2. [A02 – Cryptographic Failures](#a02)
3. [A03 – Injection](#a03)
4. [A04 – Insecure Design](#a04)
5. [A05 – Security Misconfiguration](#a05)
6. [A06 – Vulnerable & Outdated Components](#a06)
7. [A07 – Identification & Authentication Failures](#a07)
8. [A08 – Software & Data Integrity Failures](#a08)
9. [A09 – Security Logging & Monitoring Failures](#a09)
10. [A10 – Server-Side Request Forgery (SSRF)](#a10)

---

## A01 – Broken Access Control {#a01}

### What to look for
- Missing authorization checks before resource access
- Horizontal privilege escalation (user A accessing user B's data)
- Vertical privilege escalation (low-privilege user accessing admin endpoints)
- IDOR (Insecure Direct Object Reference) — using user-controlled IDs without ownership checks
- CORS misconfiguration allowing untrusted origins

### Language-specific patterns

**Python/Flask/Django**
```python
# VULNERABLE – no ownership check
@app.route('/document/<doc_id>')
def get_document(doc_id):
    return Document.query.get(doc_id)  # any user can fetch any doc

# SECURE
def get_document(doc_id):
    doc = Document.query.get(doc_id)
    if doc.owner_id != current_user.id:
        abort(403)
    return doc
```

**JavaScript/Node/Express**
```js
// VULNERABLE
app.get('/api/orders/:id', async (req, res) => {
    const order = await Order.findById(req.params.id);
    res.json(order);
});

// SECURE
app.get('/api/orders/:id', async (req, res) => {
    const order = await Order.findOne({ _id: req.params.id, userId: req.user.id });
    if (!order) return res.status(403).json({ error: 'Forbidden' });
    res.json(order);
});
```

**Java/Spring**
```java
// VULNERABLE – no @PreAuthorize or manual check
@GetMapping("/admin/users")
public List<User> getAllUsers() { return userRepo.findAll(); }

// SECURE
@PreAuthorize("hasRole('ADMIN')")
@GetMapping("/admin/users")
public List<User> getAllUsers() { return userRepo.findAll(); }
```

---

## A02 – Cryptographic Failures {#a02}

### What to look for
- Hardcoded secrets, API keys, passwords in source
- Weak/broken algorithms: MD5, SHA1, DES, RC4
- Missing TLS / HTTP instead of HTTPS
- Weak key sizes (RSA < 2048, AES < 128)
- Insecure random number generation for security-sensitive values
- Secrets stored in logs or error messages

### Patterns to flag (all languages)
```
# Hardcoded secrets
password = "supersecret123"
api_key = "sk-live-..."
SECRET_KEY = "hardcoded-value"
AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"

# Weak hashing
md5(password)
sha1(data)
hashlib.md5(...)

# Weak random
random.random()         # Python – not cryptographically secure
Math.random()           # JS – not cryptographically secure
new Random()            # Java – not cryptographically secure

# Use instead
secrets.token_hex()     # Python
crypto.randomBytes()    # Node.js
SecureRandom()          # Java
```

---

## A03 – Injection {#a03}

### SQL Injection

**Python**
```python
# VULNERABLE
cursor.execute("SELECT * FROM users WHERE name = '" + username + "'")
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# SECURE
cursor.execute("SELECT * FROM users WHERE name = %s", (username,))
```

**Node.js**
```js
// VULNERABLE
db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)

// SECURE
db.query('SELECT * FROM users WHERE id = ?', [req.params.id])
```

**Java**
```java
// VULNERABLE
stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);

// SECURE
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
ps.setInt(1, userId);
```

### Command Injection
```python
# VULNERABLE
os.system("ping " + user_input)
subprocess.call("ls " + path, shell=True)

# SECURE
subprocess.run(["ping", user_input])
subprocess.run(["ls", path])
```

### XSS (Server-side rendering)
```python
# VULNERABLE – unescaped output
return f"<h1>Hello {username}</h1>"

# SECURE – use template engine escaping
return render_template('hello.html', username=username)
```

---

## A04 – Insecure Design {#a04}

### What to look for
- No rate limiting on sensitive endpoints (login, password reset, OTP)
- Missing input validation / business logic controls
- Predictable resource identifiers (sequential IDs)
- Lack of anti-automation controls

---

## A05 – Security Misconfiguration {#a05}

### What to look for
- Debug mode enabled in production
- Default credentials not changed
- Overly permissive CORS (`Access-Control-Allow-Origin: *` on APIs with auth)
- Stack traces or verbose errors returned to client
- Unnecessary HTTP methods enabled (PUT/DELETE on public endpoints)
- Missing security headers

```python
# VULNERABLE – Flask debug on
app.run(debug=True)

# VULNERABLE – Django
DEBUG = True
ALLOWED_HOSTS = ['*']

# VULNERABLE – CORS
CORS(app, origins="*")
```

**Missing security headers to flag:**
- `Content-Security-Policy`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Strict-Transport-Security`
- `Referrer-Policy`

---

## A06 – Vulnerable & Outdated Components {#a06}

Handled by dependency analysis phase. Reference `cve-patterns.md` for known bad versions.

---

## A07 – Identification & Authentication Failures {#a07}

### What to look for
- Weak password policies (no minimum length, no complexity)
- Missing brute-force protection on login
- Passwords stored in plaintext or with weak hashing (MD5/SHA1)
- JWT issues: `alg: none`, weak secrets, no expiry
- Session tokens in URLs
- Missing MFA on sensitive actions

```python
# VULNERABLE – plain MD5 for passwords
hashed = hashlib.md5(password.encode()).hexdigest()

# SECURE
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# VULNERABLE JWT
jwt.decode(token, options={"verify_signature": False})
```

---

## A08 – Software & Data Integrity Failures {#a08}

### What to look for
- Deserializing untrusted data without validation
- `pickle.loads()` on user input (Python)
- `ObjectInputStream` on untrusted data (Java)
- Missing subresource integrity (SRI) on CDN scripts
- Unsigned software updates

```python
# VULNERABLE
obj = pickle.loads(user_supplied_bytes)

# VULNERABLE
yaml.load(user_input)        # use yaml.safe_load()
```

---

## A09 – Security Logging & Monitoring Failures {#a09}

### What to look for
- Passwords or tokens logged
- No logging of authentication events
- No logging of access control failures
- PII (emails, SSNs, card numbers) in logs

```python
# VULNERABLE
logger.info(f"Login attempt: user={username} password={password}")

# SECURE
logger.info(f"Login attempt: user={username}")
logger.warning(f"Failed login for user={username} from ip={ip}")
```

---

## A10 – Server-Side Request Forgery (SSRF) {#a10}

### What to look for
- User-controlled URLs fetched server-side without allowlist validation
- Internal network requests triggered by user input
- Cloud metadata endpoint access (`169.254.169.254`)

```python
# VULNERABLE
url = request.args.get('url')
response = requests.get(url)

# SECURE – allowlist domains
ALLOWED_HOSTS = ['api.trustedpartner.com']
parsed = urlparse(url)
if parsed.hostname not in ALLOWED_HOSTS:
    abort(400)
response = requests.get(url)
```
