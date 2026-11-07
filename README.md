# Employee phone management

Small same-origin HTML/CSS/JavaScript frontend and Go server. No frontend dependencies or build step. The sole direct Go dependency is go-ldap for Active Directory access over verified LDAPS.

## Run and integrate

Install Go 1.26 or later, then configure these environment variables (example PowerShell):

```powershell
$env:PUBLIC_ORIGIN = 'https://phones.example.com'
$env:AD_URL = 'ldaps://dc.example.com:636'
$env:AD_ALLOWED_OUS = 'OU=Employees,DC=example,DC=com'
$env:AD_PHONE_ATTRIBUTE = 'telephoneNumber'
$env:PHONE_PATTERN = '[+0-9(). -]{3,32}'
$env:AD_BIND_DN = 'CN=Phone Service,OU=Services,DC=example,DC=com'
# Inject AD_BIND_PASSWORD using your deployment secret manager.
go mod tidy
go test ./...
go run .
```

`go mod tidy` resolves the pinned dependencies; go.sum records their checksums. Source assets are embedded in the binary (`go build .`); restart/rebuild after editing them.

Terminate HTTPS at a reverse proxy on PUBLIC_ORIGIN and forward every path to `127.0.0.1:8080`, preserving the browser Origin header. Do not expose port 8080 publicly. Secure cookies deliberately require HTTPS, including local development. Install your enterprise CA in the server's trust store; never disable TLS certificate verification. PUBLIC_ORIGIN has no trailing slash.

Delegate the service account read access to the relevant employee OU and write access **only to the configured attribute** for those employees. Use a non-administrative account. Username accepts sAMAccountName or full userPrincipalName. Passwords are used for a separate employee bind and discarded; employee passwords are never retained in sessions. Disabled accounts are excluded. Login is limited to five attempts per normalized username per minute, thirty globally per minute, and eight concurrent binds. Counters are capped at 10,000 entries and fail closed when full. Username aliases share only the global limit; match these bounds to AD lockout policy and add proxy per-source limits. Forwarded IP headers are deliberately not trusted.

## API contract

All API replies are JSON with `Cache-Control: no-store`. Errors are `{ "error": "human-readable message" }`. The server never takes a target user, DN, or employee ID from a request.

| Request | Body | Successful response |
| --- | --- | --- |
| `GET /api/me` | none | `{ "user": { "name": "Alice", "username": "alice", "phone": "123", "version": "opaque-value" }, "csrfToken": "…" }` |
| `POST /api/login` | `{ "username": "alice", "password": "…" }` | same profile response; session and CSRF token rotate |
| `PUT /api/me/phone` | `{ "phone": "+1 212 555 0100", "version": "value from profile" }` | same profile response, after atomic AD modify succeeds and readback on the same connection confirms the number |
| `POST /api/logout` | none | `{ "csrfToken": "…" }`; authenticated session is replaced with an anonymous session |

First call GET /api/me. A missing/expired session returns **401**, a fresh anonymous `__Host-epm` cookie, and `{ "error": "Please sign in to continue.", "csrfToken": "…" }`. This token protects the login too. Every POST/PUT must include `X-CSRF-Token` and the exact PUBLIC_ORIGIN Origin header. The browser supplies Origin automatically. Tokens remain only in JavaScript memory; cookies are Secure, HttpOnly, SameSite=Strict, Path=/, with no Domain. No browser storage is used. Refresh reloads the CSRF token through GET /api/me.

Validation errors use 400/422; CSRF/origin rejection 403; unsupported content type 415; missing version 428; stale/concurrent edit 409; throttled login 429; oversized body 413; unconfirmed directory requests 502. All unknown body fields are rejected. Phone numbers require 3–32 ASCII characters from digits, spaces, +, parentheses, dot and hyphen, including at least three digits. Empty numbers cannot clear the AD attribute. PHONE_PATTERN is an additional, automatically anchored Go RE2 policy within these base constraints (for example `\+[1-9][0-9]{7,14}` for an international format). The frontend provides basic syntax hints; the server enforces the configured policy.

A failed or uncertain update leaves the existing displayed number visible. A timeout can occur after AD committed a write: reload to reconcile before retrying. Only a successful modify and matching readback show success. Profile text is rendered with textContent. Both forms support keyboard submission and native labels/validation; progress and errors use live regions.

## Deployment and security boundaries

Use one named DC in AD_URL, not a load balancer, round-robin alias, or referral endpoint. Every operation re-resolves objectGUID within the configured OUs, and updates use AD GUID addressing so a reused DN cannot select another account. AD_ALLOWED_OUS is a semicolon-separated list of at most four disjoint OU DNs. An employee moved outside the list cannot be read or updated. Service-account delegation must enforce the same boundary, including during moves. Configure exactly one attribute: mobile or telephoneNumber; requests cannot choose it.

The client submits its last profile version. The server rejects stale versions and atomically deletes the exact previous value and adds the new value in one LDAP modify, without permissive-modify controls. For an unset value it uses add only. A conflicting change fails with 409; reload and review before submitting again. This protects against concurrent writes on the selected DC. AD replication is multi-master: writes through another DC can still conflict later; route all writers of this attribute to this DC or establish a single authoritative writer. Versions compare phone values; a change that returns to exactly the same value is equivalent.

Place HTTPS termination on the internal host and proxy all paths to loopback port 8080. For nginx, the location can be:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header Origin $http_origin;
    proxy_read_timeout 95s;
    client_max_body_size 4k;
}
```

Configure TLS certificates and internal DNS on the proxy; block direct backend access. Never log request bodies, cookies, CSRF headers, or authorization material at the proxy. Inject service-account secrets through your host secret manager. The application does not parse config.example.env or require a dotenv dependency. LDAPS uses OS trust roots and hostname verification; install your enterprise root/intermediate CAs in that trust store.

API bodies are capped at 4 KiB, headers at 16 KiB. HTTP header/read/write/idle timeouts are 5/15/90/60 seconds; LDAP dial and operation timeouts are 5 seconds with searches limited to five seconds and two results. At most four OUs bound cumulative directory work. SIGINT/SIGTERM drain HTTP requests for up to 90 seconds, then close connections. Set the service supervisor stop timeout above 90 seconds. Requests already admitted may finish after logout; subsequent requests cannot use that session.

Audit lines record fixed event/outcome names and hashed identity references, never passwords, phone numbers, usernames, DNs, session IDs, CSRF tokens, or raw LDAP errors. Hashes are pseudonymous, not anonymous; restrict log access and retention. Login failures, throttling, updates/conflicts/unconfirmed writes and logout are audited.

Sessions expire absolutely after 15 minutes, are bounded to 10,000 entries, and vanish on restart. At capacity a session is evicted. Run one instance; adopt a shared expiring store before adding replicas. Anonymous bootstrap sessions use the same bounds. AD remains the data source; only GUID, CSRF and expiry live in sessions. Password resets do not revoke existing sessions until expiry; disabled/deleted/out-of-scope accounts cannot load or update their profile.

## Verification

```powershell
go test ./...
go vet ./...
node --check web/app.js
```

Tests use a fake directory for HTTP/session/CSRF/identity and failure behavior, and inspect atomic LDAP modify construction. The live integration test is skipped unless AD_TEST_ENABLE=yes. On a **disposable test employee**, set AD_TEST_USERNAME, AD_TEST_PASSWORD, AD_TEST_OU (within the allowed OUs), and AD_TEST_UNTRUSTED_URL (an LDAPS endpoint with an untrusted certificate or hostname mismatch), plus the normal AD variables. Run `go test -run TestADIntegration -v`. The test re-writes the same existing phone and checks readback; it also rejects empty passwords, filter injection, stale versions and untrusted TLS. Do not use production employees or expose these secrets in shell history.

Before release, additionally exercise two-browser conflicting edits, out-of-OU and disabled users, rename/move handling, delegated-permission denial, directory/network failure, logout and expiry, proxy HTTPS and keyboard/mobile use. No live AD environment is included.

Implementation references: [AD GUID identity](https://learn.microsoft.com/en-us/windows/win32/ad/using-objectguid-to-bind-to-an-object), [AD atomic updates](https://learn.microsoft.com/en-us/windows/win32/ad/a-programmerampaposs-model-of-replication-in-active-directory-domain-services), and [go-ldap API](https://pkg.go.dev/github.com/go-ldap/ldap/v3).
