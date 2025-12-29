# Remediation Guide Templates

> *"Every vulnerability has a fix. Every fix improves security."*

---

## Injection Vulnerabilities

### SQL Injection

**Vulnerability**: User input is concatenated directly into SQL queries.

**Remediation**:

1. **Use Parameterized Queries (Prepared Statements)**

```php
// PHP - PDO
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);

// PHP - MySQLi
$stmt = $mysqli->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $id);
$stmt->execute();
```

```python
# Python - SQLAlchemy
result = db.session.execute(
    text("SELECT * FROM users WHERE id = :id"),
    {"id": user_id}
)

# Python - psycopg2
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

```java
// Java - JDBC
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
stmt.setInt(1, userId);
ResultSet rs = stmt.executeQuery();
```

```csharp
// C# - ADO.NET
using (SqlCommand cmd = new SqlCommand("SELECT * FROM users WHERE id = @id", conn))
{
    cmd.Parameters.AddWithValue("@id", userId);
    SqlDataReader reader = cmd.ExecuteReader();
}
```

2. **Use ORM Properly**
```python
# Django - Safe
User.objects.filter(id=user_id)

# Django - UNSAFE (avoid)
User.objects.raw(f"SELECT * FROM users WHERE id = {user_id}")
```

3. **Input Validation**
- Whitelist allowed characters
- Validate data types
- Enforce length limits

4. **Least Privilege Database Accounts**
- Use read-only accounts where possible
- Restrict access to specific tables/schemas

---

### Command Injection

**Vulnerability**: User input is passed to system commands.

**Remediation**:

1. **Avoid Shell Commands When Possible**
```python
# Instead of
os.system(f"convert {filename} output.png")

# Use libraries
from PIL import Image
img = Image.open(filename)
img.save("output.png")
```

2. **Use Safe APIs**
```python
# Python - subprocess with list arguments
subprocess.run(["convert", filename, "output.png"], shell=False)

# NEVER use shell=True with user input
```

```php
// PHP - escapeshellarg
$safe_file = escapeshellarg($filename);
exec("convert $safe_file output.png");
```

3. **Input Validation**
```python
import re
if not re.match(r'^[a-zA-Z0-9_.-]+$', filename):
    raise ValueError("Invalid filename")
```

---

### XSS (Cross-Site Scripting)

**Vulnerability**: User input is rendered in HTML without encoding.

**Remediation**:

1. **Output Encoding**
```php
// PHP
echo htmlspecialchars($userInput, ENT_QUOTES, 'UTF-8');
```

```python
# Python - Jinja2 (auto-escapes by default)
{{ user_input }}

# Manual escaping
from markupsafe import escape
escape(user_input)
```

```javascript
// JavaScript
element.textContent = userInput;  // Safe
element.innerHTML = userInput;    // UNSAFE
```

2. **Content Security Policy**
```http
Content-Security-Policy: default-src 'self'; script-src 'self'
```

3. **HTTPOnly Cookies**
```http
Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict
```

4. **Framework-Specific**
```jsx
// React - Safe by default
<div>{userInput}</div>

// React - UNSAFE (avoid)
<div dangerouslySetInnerHTML={{__html: userInput}} />
```

---

## Authentication & Session

### Weak Password Policy

**Remediation**:

1. **Enforce Password Complexity**
```python
import re

def validate_password(password):
    if len(password) < 12:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True
```

2. **Use Password Hashing**
```python
# Python - bcrypt
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

# Python - argon2 (recommended)
from argon2 import PasswordHasher
ph = PasswordHasher()
hashed = ph.hash(password)
```

3. **Check Against Breached Passwords**
- Use HaveIBeenPwned API
- Check against common password lists

---

### Session Management

**Remediation**:

1. **Secure Cookie Attributes**
```python
# Flask
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
```

```php
// PHP
ini_set('session.cookie_secure', 1);
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_samesite', 'Strict');
```

2. **Regenerate Session ID**
```php
// After login
session_regenerate_id(true);
```

```python
# Flask
from flask import session
session.regenerate()
```

3. **Session Timeout**
```python
# Set session lifetime
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
```

---

## Access Control

### IDOR (Insecure Direct Object Reference)

**Vulnerability**: Direct access to objects without authorization check.

**Remediation**:

1. **Always Verify Authorization**
```python
# BAD
@app.route('/document/<int:doc_id>')
def get_document(doc_id):
    return Document.query.get(doc_id)

# GOOD
@app.route('/document/<int:doc_id>')
@login_required
def get_document(doc_id):
    doc = Document.query.get(doc_id)
    if doc.owner_id != current_user.id:
        abort(403)
    return doc
```

2. **Use Indirect References**
```python
# Map user-visible IDs to actual IDs
user_docs = {
    'doc1': 12345,
    'doc2': 67890
}
```

3. **Implement Row-Level Security**
```sql
-- PostgreSQL RLS
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
CREATE POLICY user_documents ON documents
    FOR ALL
    USING (owner_id = current_user_id());
```

---

### Missing Function Level Access Control

**Remediation**:

1. **Centralized Authorization**
```python
from functools import wraps

def require_role(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.has_role(role):
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/admin/users')
@login_required
@require_role('admin')
def admin_users():
    return User.query.all()
```

2. **Default Deny**
```python
# All routes require authentication by default
@app.before_request
def require_login():
    if not current_user.is_authenticated:
        if request.endpoint not in ['login', 'public_page']:
            return redirect(url_for('login'))
```

---

## Cryptographic Issues

### Weak Encryption

**Remediation**:

1. **Use Strong Algorithms**
```python
# Symmetric encryption - Use AES-256-GCM
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(key)
nonce = os.urandom(12)
ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
```

2. **Use Secure Random**
```python
import secrets

# Generate secure random token
token = secrets.token_urlsafe(32)

# Generate secure random bytes
random_bytes = secrets.token_bytes(32)
```

3. **Avoid Deprecated Algorithms**
- No MD5, SHA1 for security purposes
- No DES, 3DES, RC4
- No ECB mode

---

### Insecure Communication

**Remediation**:

1. **Enforce HTTPS**
```nginx
# Nginx
server {
    listen 80;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
}
```

2. **HSTS Header**
```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

3. **Certificate Validation**
```python
import requests

# Verify SSL certificates (default)
response = requests.get('https://api.example.com', verify=True)

# Never disable verification in production
# verify=False is DANGEROUS
```

---

## Security Headers

### Missing Headers

**Remediation**:

```nginx
# Nginx configuration
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
```

```python
# Flask
from flask import Flask
from flask_talisman import Talisman

app = Flask(__name__)
Talisman(app, content_security_policy={
    'default-src': "'self'",
    'script-src': "'self'"
})
```

---

## File Upload

### Unrestricted File Upload

**Remediation**:

1. **Validate File Type**
```python
import magic

ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/gif']

def validate_file(file):
    # Check MIME type using magic bytes
    mime = magic.from_buffer(file.read(1024), mime=True)
    file.seek(0)

    if mime not in ALLOWED_TYPES:
        raise ValueError("Invalid file type")

    # Also check extension
    ext = file.filename.rsplit('.', 1)[1].lower()
    if ext not in ['jpg', 'jpeg', 'png', 'gif']:
        raise ValueError("Invalid extension")
```

2. **Store Outside Webroot**
```python
# Store uploads outside web-accessible directory
UPLOAD_FOLDER = '/var/uploads/'  # Not in /var/www/

# Serve through application
@app.route('/files/<filename>')
@login_required
def serve_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)
```

3. **Rename Files**
```python
import uuid

def safe_filename(original):
    ext = original.rsplit('.', 1)[1].lower()
    return f"{uuid.uuid4()}.{ext}"
```

---

## API Security

### Rate Limiting

**Remediation**:

```python
# Flask-Limiter
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.route("/api/login")
@limiter.limit("5 per minute")
def login():
    pass
```

```nginx
# Nginx rate limiting
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;

location /api/ {
    limit_req zone=api burst=20 nodelay;
}
```

---

### API Authentication

**Remediation**:

```python
# JWT validation
from functools import wraps
import jwt

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Missing token'}), 401
        try:
            token = token.split(' ')[1]  # Remove 'Bearer '
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated
```

---

## Quick Remediation Checklist

| Vulnerability | Primary Fix | Secondary Controls |
|--------------|-------------|-------------------|
| SQL Injection | Parameterized queries | Input validation, WAF |
| XSS | Output encoding | CSP, HTTPOnly cookies |
| CSRF | Anti-CSRF tokens | SameSite cookies |
| IDOR | Authorization checks | Indirect references |
| Auth Bypass | Proper auth logic | MFA, rate limiting |
| File Upload | Validation, rename | Store outside webroot |
| Command Injection | Avoid shell, safe APIs | Input validation |
| SSRF | Allowlist URLs | Network segmentation |
| XXE | Disable DTDs | Input validation |
| Deserialization | Avoid if possible | Type checking |

---

## Verification Steps

After implementing fixes:

1. **Retest with same payload** - Confirm original attack fails
2. **Try bypass techniques** - Test encoding, alternate methods
3. **Automated scan** - Run scanner again
4. **Regression testing** - Ensure functionality still works
5. **Code review** - Verify fix is applied correctly
