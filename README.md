# omnibioai-api-gateway

**Zero-trust API gateway for the OmniBioAI platform.**

Single enforced entry point for all service traffic. Every request
is authenticated, authorized, quota-checked, and audited before
reaching any backend service.

---

## Architecture

```
Internet / Client / Studio

↓

api-gateway :8080        ← single entry point

↓

TraceMiddleware          ← generates X-Trace-Id UUID

↓

AuthMiddleware           ← JWT validation via IAM client + Redis cache

↓

PolicyMiddleware         ← RBAC/ABAC via policy-engine

↓

HPCMiddleware            ← GPU/CPU quota via hpc-policy-engine (compute paths only)

↓

AuditMiddleware          ← async audit log via security-audit

↓

target service           ← workbench / tes / toolserver / model-registry / rag
```

**Failure policy:**

| Layer | On failure |
|-------|-----------|
| Auth | FAIL CLOSED → HTTP 401 |
| Policy | FAIL CLOSED → HTTP 403 |
| HPC quota | FAIL CLOSED → HTTP 403 |
| Audit | FAIL OPEN → ignored |

---

## Authentication Pipeline

Every request that isn't `/health` or `/` passes through this exact chain
(`app/main.py`; middleware is registered LIFO, so `TraceMiddleware` —
added last — runs first):

```
Incoming JWT
      │   Authorization: Bearer <jwt>
      ▼
IAM validation      AuthMiddleware → IAMClient.validate(token)
      │              — Redis-cached (key "iam:{token}", TTL 300s) first,
      │                else POST {IAM_URL}/auth/validate (1 retry on timeout)
      │              — no token or a rejected token → 401, fail closed
      ▼
Policy               PolicyMiddleware → PolicyClient.evaluate(...)
      │              — POSTs user_id/email/roles/permissions/action/resource
      │                to {POLICY_URL}/policy/evaluate
      │              — `action` is the target service's mapped IAM
      │                permission when one exists (SERVICE_PERMISSION_MAP
      │                in app/core/router.py: workbench/tes/toolserver →
      │                workflow.execute, model-registry → model.use,
      │                rag → dataset.read), else a derived
      │                "{method}.{path}" string — this mapping only
      │                enriches what the policy engine evaluates against;
      │                the engine's remote decision is still the sole
      │                allow/deny authority
      │              — deny → 403, fail closed
      │              (HPCMiddleware runs next, compute paths only —
      │               GPU/CPU quota via {HPC_URL}/jobs/evaluate, also
      │               fail-closed)
      ▼
Forward Authorization header
      │              gateway.py rebuilds the outgoing header set from
      │                scratch (never re-forwards the raw incoming
      │                "authorization" key) and sets
      │                Authorization: Bearer <token> from
      │                request.state.token — the exact string
      │                AuthMiddleware already validated, not a re-parse
      │                of the original header — so the backend service
      │                can independently re-verify identity itself.
      ▼
Backend services     proxy.forward() to the resolved SERVICE_MAP target
                       (workbench / tes / toolserver / model-registry / rag)
```

The gateway never decodes a JWT itself — no local HS256/RS256 verification,
no JWKS client. Every validation is a remote call to auth-service's
`/auth/validate` (Redis-cached), delegating entirely to the shared identity
layer described in [omnibioai-auth's README](../omnibioai-auth#jwt) rather
than duplicating its verification logic.

### Identity propagation

Alongside the re-forwarded `Authorization` header, the gateway also injects:

| Header | Value | Notes |
|--------|-------|-------|
| `X-User-Id` | The authenticated user's ID | **Unsigned** — a convenience header for services that don't want to re-decode the JWT; the re-forwarded `Authorization` bearer token is the only header a backend should actually trust for authorization decisions |
| `X-Internal-Service` | `gateway` | Marks the request as gateway-verified/internal |

`org_id`/`org_role` are resolved into `request.state.user` during IAM
validation but are **not** propagated as their own headers today — a
backend that needs them re-derives them from the forwarded JWT itself
(`/auth/validate` or a local `jwt_verify.py`, same as Control Center and
Security Audit do).

### Authorization forwarding

See "Forward Authorization header" in the pipeline above — this is not a
service-to-service token, it is the caller's own validated bearer token,
forwarded as-is so the backend service can verify it independently rather
than trusting the gateway's decision blindly.

### Trace IDs

`TraceMiddleware` (outermost — runs first) generates or echoes an
`X-Trace-Id` UUID, attaches it to `request.state.trace_id`, sets it on the
response, and it's propagated on to the backend request. Every
middleware's own audit events (auth/policy/HPC denials, the final
upstream-forward event) carry this same trace ID, so a single request can
be followed end-to-end through the audit stream.

### Service identity

There is currently no separate service-to-service credential (no service
JWT, no mTLS, no API key) — the gateway calls backend services carrying
only the unsigned `X-Internal-Service: gateway` marker plus the forwarded
user bearer token. Backend-to-backend trust within the compose network is
not independently authenticated at the gateway layer; each backend service
is expected to validate the forwarded JWT itself if it needs a real
identity guarantee.

---

## Features

- JWT authentication via IAM client (Redis-cached, sub-ms validation)
- RBAC/ABAC policy enforcement on every request
- GPU/CPU quota governance for compute requests
- Async audit logging via Redis Streams (never blocks requests)
- Original bearer-token forwarding to backend services (see [Authentication Pipeline](#authentication-pipeline))
- Distributed trace ID propagation (X-Trace-Id header)
- Redis pub/sub cache invalidation on logout
- Rate limiting on auth endpoints (via nginx — 10 req/min, burst 5)

---

## Middleware Stack

Middleware is applied LIFO — last added runs first for requests:

| Order | Middleware | Responsibility |
|-------|-----------|----------------|
| 1 | TraceMiddleware | Generate X-Trace-Id, attach to request state |
| 2 | AuthMiddleware | Validate JWT via IAM client |
| 3 | PolicyMiddleware | RBAC/ABAC authorization decision |
| 4 | HPCMiddleware | GPU/CPU quota check (compute paths only) |
| 5 | AuditMiddleware | Fire async audit event to Redis Streams |

---

## Repository Structure

```text
app/
├── main.py                    # Registers middleware (LIFO) and routers
├── core/
│   ├── config.py               # Settings from environment
│   ├── router.py               # SERVICE_MAP, SERVICE_PERMISSION_MAP,
│   │                            # resolve_service(), resolve_required_permission()
│   ├── permissions.py          # require_permission() dependency — for
│   │                            # gateway-native routes only (e.g. /auth/verify),
│   │                            # deliberately not wired into the proxy route
│   │                            # to avoid duplicating PolicyMiddleware's decision
│   └── security.py             # Trace-ID generation + its own audit event
├── middleware/
│   ├── s2s.py                  # TraceMiddleware (name predates current scope —
│   │                            # this is not a service-to-service credential
│   │                            # system; see "Service identity" above)
│   ├── auth.py                 # AuthMiddleware
│   ├── policy.py               # PolicyMiddleware
│   ├── hpc.py                  # HPCMiddleware
│   └── audit.py                # AuditMiddleware
├── routes/
│   ├── auth_verify.py          # GET /auth/verify
│   └── gateway.py              # Catch-all proxy route
└── services/
    ├── iam_client.py           # IAM validation client
    ├── policy_client.py        # Policy engine client
    ├── hpc_policy_client.py    # HPC policy engine client
    └── audit_client.py         # Audit event client
```

---

## API Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/health` | GET | — | Gateway health check |
| `/auth/verify` | GET | JWT | Verify token (used by nginx auth_request) |
| `/{service}/{path}` | GET/POST/PUT/DELETE | JWT | Proxy to target service — no `/api` prefix |

### Health check
```bash
curl http://localhost:8080/health
# {"status": "ok"}
```

### All other requests require JWT
```bash
curl -H "Authorization: Bearer <token>" \
  http://localhost:8080/tes/jobs
```

---

## Service Routing

| Path | Target service |
|------|-----------------|
| `/workbench/*` | workbench :8000 |
| `/tes/*` | tes :8081 |
| `/toolserver/*` | toolserver :9090 |
| `/model-registry/*` | model-registry :8095 |
| `/rag/*` | rag :8096 |

LIMS is not proxied through this gateway's `SERVICE_MAP` — it's reached
via a separate route.

---

## Internal Headers Propagated

| Header | Description |
|--------|-------------|
| `Authorization` | The caller's original bearer token, re-forwarded verbatim (see [Authentication Pipeline](#authentication-pipeline)) |
| `X-Trace-Id` | UUID per request for distributed tracing |
| `X-User-Id` | Authenticated user ID (unsigned convenience header) |
| `X-Internal-Service` | Marks request as internal (gateway-verified) |

---

## Running

### Via OmniBioAI Studio (recommended)

```bash
cd ~/Desktop/machine/omnibioai-studio
docker compose up -d api-gateway
```

Access: `http://localhost:8080`

### Environment variables

Set in `omnibioai-studio/.env`:

| Variable | Default | Description |
|----------|---------|-------------|
| `IAM_URL` | `http://omnibioai-auth:8000` | Auth service URL |
| `POLICY_URL` | `http://omnibioai-policy-engine:8001` | Policy engine URL |
| `HPC_URL` | `http://omnibioai-hpc-policy-engine:8002` | HPC policy URL |
| `REDIS_URL` | `redis://redis:6379` | Redis for token cache + pub/sub |
| `JWT_SECRET` | — | JWT signing secret (auto-generated) |
| `ROUTE_TIMEOUT` | `15` | Upstream request timeout (seconds) |

---

## Testing

```bash
cd ~/Desktop/machine/omnibioai-api-gateway
pytest tests/ -v --cov=app

# 179 tests passing
# 99% coverage
# Covers: auth middleware, policy middleware, HPC middleware,
#         trace middleware, audit middleware, config, gateway router,
#         permissions dependency, and the PR12/PR13 middleware-chain
#         end-to-end + org-context/role-tier forwarding suites
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Framework | FastAPI + Uvicorn |
| Auth | IAM client (httpx async + Redis cache) |
| Cache invalidation | Redis pub/sub |
| Tracing | UUID trace IDs via middleware |
| Proxying | httpx reverse proxy |

---

## Related Services

| Service | Role |
|---------|------|
| `omnibioai-auth` | JWT issuance and validation |
| `omnibioai-iam-client` | Async IAM client with Redis cache |
| `omnibioai-policy-engine` | RBAC/ABAC authorization decisions |
| `omnibioai-hpc-policy-engine` | GPU/CPU quota governance |
| `omnibioai-security-audit` | Async audit event consumer |
| `omnibioai-security-sdk` | SDK wrapping the full security stack |
| `omnibioai-studio` | Manages gateway container lifecycle |

---

## License

Apache 2.0

---

*Part of the [OmniBioAI](https://github.com/OmniBioAI/omnibioai-studio) platform.*
