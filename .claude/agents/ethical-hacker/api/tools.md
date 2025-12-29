# INTERCEPTOR Tools Reference

> *"The right tool intercepts the right traffic."*

## API Testing Tools

### Postman
**Source**: https://www.postman.com/

```bash
# Import API specification
# File > Import > OpenAPI/Swagger

# Key features:
# - Collection organization
# - Environment variables
# - Pre-request scripts
# - Test automation
# - Authentication helpers
```

### curl
**Source**: https://curl.se/

```bash
# GET request
curl -X GET "http://$TARGET/api/v1/users" -H "Authorization: Bearer $TOKEN"

# POST with JSON
curl -X POST "http://$TARGET/api/v1/users" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name": "test", "email": "test@test.com"}'

# PUT request
curl -X PUT "http://$TARGET/api/v1/users/1" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name": "updated"}'

# DELETE request
curl -X DELETE "http://$TARGET/api/v1/users/1" \
  -H "Authorization: Bearer $TOKEN"

# With cookies
curl -X GET "http://$TARGET/api/v1/profile" \
  -b "session=abc123"

# Verbose output
curl -v "http://$TARGET/api/v1/users"

# Follow redirects
curl -L "http://$TARGET/api/v1/redirect"

# Save response to file
curl -o response.json "http://$TARGET/api/v1/users"

# Include response headers
curl -i "http://$TARGET/api/v1/users"
```

### httpie
**Source**: https://httpie.io/

```bash
# GET request
http GET "$TARGET/api/v1/users" "Authorization:Bearer $TOKEN"

# POST with JSON
http POST "$TARGET/api/v1/users" name=test email=test@test.com "Authorization:Bearer $TOKEN"

# PUT request
http PUT "$TARGET/api/v1/users/1" name=updated "Authorization:Bearer $TOKEN"

# With session
http --session=./session.json GET "$TARGET/api/v1/profile"

# Form data
http -f POST "$TARGET/api/v1/login" username=admin password=test

# Custom headers
http GET "$TARGET/api/v1/users" "X-Custom-Header:value"
```

## JWT Tools

### jwt_tool
**Source**: https://github.com/ticarpi/jwt_tool

```bash
# Decode JWT
python3 jwt_tool.py $JWT

# Scan for vulnerabilities
python3 jwt_tool.py $JWT -M at

# Test none algorithm
python3 jwt_tool.py $JWT -X a

# Test null signature
python3 jwt_tool.py $JWT -X n

# Crack secret (dictionary)
python3 jwt_tool.py $JWT -C -d /usr/share/wordlists/rockyou.txt

# Tamper claims
python3 jwt_tool.py $JWT -T

# Inject header
python3 jwt_tool.py $JWT -I -hc kid -hv "../../etc/passwd"

# Test algorithm confusion
python3 jwt_tool.py $JWT -X k -pk public.pem
```

### jwt-cracker
**Source**: https://github.com/brendan-rius/c-jwt-cracker

```bash
# Brute force secret
./jwtcrack $JWT

# With character set
./jwtcrack $JWT -c "abcdefghijklmnopqrstuvwxyz0123456789"
```

### jwt.io (Online decoder)
```
# Paste JWT at https://jwt.io
# Analyze header, payload, signature
```

## API Discovery

### Kiterunner
**Source**: https://github.com/assetnote/kiterunner

```bash
# Scan for API endpoints
kr scan $TARGET -w routes-large.kite

# With wordlist
kr scan $TARGET -w /path/to/wordlist.txt

# Brute force mode
kr brute $TARGET -w wordlist.txt

# Headers
kr scan $TARGET -w routes.kite -H "Authorization: Bearer $TOKEN"
```

### Arjun (Parameter discovery)
**Source**: https://github.com/s0md3v/Arjun

```bash
# Find GET parameters
arjun -u "http://$TARGET/api/v1/search"

# Find POST parameters
arjun -u "http://$TARGET/api/v1/users" -m POST

# JSON parameters
arjun -u "http://$TARGET/api/v1/users" -m JSON

# With headers
arjun -u "http://$TARGET/api/v1/users" --headers "Authorization: Bearer $TOKEN"
```

### ffuf (API fuzzing)
**Source**: https://github.com/ffuf/ffuf

```bash
# Endpoint discovery
ffuf -u "http://$TARGET/api/v1/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt

# Parameter fuzzing
ffuf -u "http://$TARGET/api/v1/users?FUZZ=test" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt

# ID enumeration
ffuf -u "http://$TARGET/api/v1/users/FUZZ" -w <(seq 1 1000) -H "Authorization: Bearer $TOKEN"

# Method fuzzing
ffuf -u "http://$TARGET/api/v1/admin" -w methods.txt -X FUZZ
# methods.txt: GET, POST, PUT, DELETE, PATCH, OPTIONS

# Version fuzzing
ffuf -u "http://$TARGET/api/FUZZ/users" -w versions.txt
# versions.txt: v1, v2, v3, beta, internal, admin
```

## GraphQL Tools

### graphqlmap
**Source**: https://github.com/swisskyrepo/GraphQLmap

```bash
# Start interactive mode
python3 graphqlmap.py -u "http://$TARGET/graphql"

# Dump schema
python3 graphqlmap.py -u "http://$TARGET/graphql" --dump

# Execute query
python3 graphqlmap.py -u "http://$TARGET/graphql" -q "{ users { id name } }"
```

### InQL (Burp Extension)
**Source**: https://github.com/doyensec/inql

```bash
# Use via Burp Suite
# Features:
# - Schema introspection
# - Query generator
# - Batch attacks
# - Scanner
```

### graphql-cop
**Source**: https://github.com/dolevf/graphql-cop

```bash
# Security audit
python3 graphql-cop.py -t "http://$TARGET/graphql"
```

### GraphQL Introspection Queries

```bash
# Basic introspection
curl -X POST "http://$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query": "{__schema{types{name fields{name}}}}"}'

# Full introspection
curl -X POST "http://$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query": "query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { ...FullType } directives { name description locations args { ...InputValue } } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }"}'
```

## Proxy Tools

### mitmproxy
**Source**: https://mitmproxy.org/

```bash
# Start proxy
mitmproxy -p 8080

# Dump traffic
mitmdump -w api_traffic.mitm

# Replay traffic
mitmdump -r api_traffic.mitm

# Scripted interception
mitmproxy -s modify_requests.py

# Example script (modify_requests.py):
# def request(flow):
#     if "api" in flow.request.pretty_url:
#         flow.request.headers["X-Test"] = "modified"
```

### Burp Suite
```bash
# Configure API testing:
# 1. Set up proxy (127.0.0.1:8080)
# 2. Import API spec
# 3. Use Repeater for manual testing
# 4. Use Intruder for fuzzing
# 5. Use Scanner for automated testing
```

## BOLA/IDOR Testing

### Manual Testing Script

```bash
#!/bin/bash
# bola_test.sh - Test for BOLA vulnerabilities

TARGET=$1
TOKEN=$2
ENDPOINT=$3

echo "Testing BOLA on $ENDPOINT"

# Test sequential IDs
for id in $(seq 1 100); do
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        "$TARGET$ENDPOINT/$id" \
        -H "Authorization: Bearer $TOKEN")

    if [ "$response" == "200" ]; then
        echo "[+] ID $id: Accessible (200)"
    fi
done
```

### Autorize (Burp Extension)
```
# Features:
# - Automatic authorization testing
# - Compare authenticated vs unauthenticated
# - Compare different user contexts
```

## Rate Limit Testing

```bash
#!/bin/bash
# rate_limit_test.sh - Test rate limiting

TARGET=$1
ENDPOINT=$2
COUNT=${3:-100}

echo "Testing rate limit on $TARGET$ENDPOINT"

for i in $(seq 1 $COUNT); do
    response=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET$ENDPOINT")
    echo "Request $i: $response"

    if [ "$response" == "429" ]; then
        echo "[!] Rate limited at request $i"
        break
    fi
done
```

## API Documentation Extraction

```bash
# Common documentation paths
paths=(
    "/api/swagger.json"
    "/api/swagger.yaml"
    "/api/openapi.json"
    "/api/openapi.yaml"
    "/swagger.json"
    "/openapi.json"
    "/api-docs"
    "/api/docs"
    "/docs/api"
    "/swagger-ui.html"
    "/swagger-ui/"
    "/redoc"
    "/graphql"
    "/.well-known/openapi.json"
)

for path in "${paths[@]}"; do
    response=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET$path")
    if [ "$response" == "200" ]; then
        echo "[+] Found: $TARGET$path"
    fi
done
```

## Quick Reference

```bash
# JWT decode
echo $JWT | cut -d'.' -f2 | base64 -d 2>/dev/null | jq .

# Quick BOLA test
for i in {1..10}; do curl -s "$TARGET/api/users/$i" -H "Authorization: Bearer $TOKEN" | jq .id; done

# GraphQL introspection
curl -s -X POST "$TARGET/graphql" -H "Content-Type: application/json" -d '{"query":"{__schema{types{name}}}"}' | jq .

# Find API endpoints
ffuf -u "$TARGET/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200,201,401,403

# Test HTTP methods
for method in GET POST PUT DELETE PATCH OPTIONS; do echo "$method:"; curl -s -X $method "$TARGET/api/endpoint" -o /dev/null -w "%{http_code}\n"; done
```

## Output Organization

```bash
# Create API testing directory
mkdir -p api/{requests,responses,findings,tokens}

# Save API documentation
curl -s "$TARGET/swagger.json" > api/swagger.json

# Save interesting responses
curl -s "$TARGET/api/users" > api/responses/users.json

# Document tokens
echo "Access Token: $TOKEN" > api/tokens/tokens.txt
```
