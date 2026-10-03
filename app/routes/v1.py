"""Public, versioned API: /v1/literature/*.

The authenticated catch-all (/{service}/{path}) forwards anything; this
router is the stable, billable contract external developers integrate
against. On top of the middleware chain (auth incl. omni_sk_ API keys,
policy, audit) every /v1 call gets:

- a per-caller rate limit (X-RateLimit-* headers, 429 + Retry-After),
- an org-level quota check maintained by omnibioai-billing (402),
- optional Idempotency-Key replay, so a retried request is never run or
  billed twice,
- exactly one billable usage event per successful billable call,
- one error shape: {"error": {"type", "message", "request_id"}}.

Request and response bodies of /v1/literature/answers are omnibioai-rag's
own POST /v1/query contract, passed through unchanged.
"""
import re

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.core.config import Config
from app.core.router import resolve_service
from app.routes.gateway import build_upstream_headers, proxy
from app.services.v1_store import V1Store, request_fingerprint

router = APIRouter(prefix="/v1")
store = V1Store(Config.V1_REDIS_URL, Config.USAGE_REDIS_URL)

ANSWER_RESOURCE = "literature.answer"
_IDEMPOTENCY_KEY = re.compile(r"^[\x21-\x7e]{1,255}$")


def _error(status: int, error_type: str, message: str, request_id: str, headers: dict | None = None, detail=None):
    body = {"error": {"type": error_type, "message": message, "request_id": request_id}}
    if detail is not None:
        body["error"]["detail"] = detail
    return JSONResponse(body, status_code=status, headers={**(headers or {}), "X-Request-Id": request_id})


def _caller(request: Request) -> tuple[str, str, str]:
    """(rate-limit subject, organization id, user id) for the verified
    identity -- an API key is limited per key, a session per user."""
    identity = getattr(request.state, "identity", None) or {}
    user_id = str(identity.get("user_id") or "")
    org_id = str(identity.get("organization_id") or "")
    subject = identity.get("client_id") or f"user:{user_id}"
    return subject, org_id, user_id


async def _rate_limited(request: Request, subject: str, request_id: str):
    limit = Config.V1_RATE_LIMIT_PER_MINUTE
    allowed, remaining, reset = await store.hit_rate_limit(subject, limit)
    headers = {
        "X-RateLimit-Limit": str(limit),
        "X-RateLimit-Remaining": str(remaining),
        "X-RateLimit-Reset": str(reset),
    }
    if not allowed:
        return headers, _error(
            429, "rate_limit_exceeded", f"More than {limit} requests per minute.", request_id,
            headers={**headers, "Retry-After": str(reset)},
        )
    return headers, None


async def _forward(request: Request, method: str, path: str, body=None):
    url = f"{resolve_service('rag')}/{path}"
    if request.url.query:
        url = f"{url}?{request.url.query}"
    return await proxy.forward(url=url, method=method, headers=build_upstream_headers(request), body=body)


def _upstream_error(status: int, response, request_id: str, headers: dict):
    if status >= 500:
        return _error(502 if status == 500 else status, "upstream_error",
                      "The literature service failed to answer. You were not charged.", request_id, headers)
    return _error(status, "invalid_request" if status in (400, 422) else "request_failed",
                  "The literature service rejected the request.", request_id, headers, detail=response)


@router.post("/literature/answers")
async def literature_answers(request: Request):
    request_id = getattr(request.state, "trace_id", "")
    subject, org_id, user_id = _caller(request)
    if not org_id:
        return _error(403, "organization_required",
                      "This API is billed to an organization; your account has none.", request_id)

    try:
        body = await request.json()
    except Exception:
        return _error(400, "invalid_request", "Request body must be JSON.", request_id)

    headers, limited = await _rate_limited(request, subject, request_id)
    if limited:
        return limited

    idempotency_key = request.headers.get("Idempotency-Key")
    fingerprint = request_fingerprint(body)
    if idempotency_key is not None:
        if not _IDEMPOTENCY_KEY.match(idempotency_key):
            return _error(400, "invalid_request", "Idempotency-Key must be 1-255 printable characters.",
                          request_id, headers)
        claim = await store.idempotency_begin(subject, idempotency_key, fingerprint)
        if claim["state"] == "replay":
            return JSONResponse(claim["body"], status_code=claim["status"],
                                headers={**headers, "X-Request-Id": request_id, "Idempotent-Replayed": "true"})
        if claim["state"] == "mismatch":
            return _error(422, "idempotency_key_reused",
                          "This Idempotency-Key was already used with a different request.", request_id, headers)
        if claim["state"] == "in_progress":
            return _error(409, "idempotency_in_progress",
                          "A request with this Idempotency-Key is still running.", request_id, headers)

    remaining = await store.quota_remaining(org_id, ANSWER_RESOURCE)
    if remaining is not None and remaining <= 0:
        if idempotency_key is not None:
            await store.idempotency_finish(subject, idempotency_key, fingerprint, 402, None)
        return _error(402, "quota_exceeded",
                      "Your organization has used its included answers. Add a payment method or upgrade the plan.",
                      request_id, headers)

    status, response = await _forward(request, "POST", "v1/query", body)

    if idempotency_key is not None:
        await store.idempotency_finish(subject, idempotency_key, fingerprint, status, response)
    if not 200 <= status < 300:
        return _upstream_error(status, response, request_id, headers)

    identity = getattr(request.state, "identity", None) or {}
    await store.emit_usage(
        org_id=org_id,
        user_id=user_id,
        resource=ANSWER_RESOURCE,
        trace_id=request_id,
        dedup_key=f"{subject}:{idempotency_key}" if idempotency_key else request_id,
        metadata={
            "request_id": request_id,
            "client_id": identity.get("client_id"),
            "token_type": identity.get("token_type"),
            "idempotency_key_sha256": request_fingerprint(idempotency_key) if idempotency_key else None,
        },
    )
    await store.consume_quota(org_id, ANSWER_RESOURCE)
    return JSONResponse(response, status_code=status, headers={**headers, "X-Request-Id": request_id})


@router.get("/literature/studies")
async def literature_studies(request: Request):
    """Free: the queryable studies/domains, from omnibioai-rag GET /v1/studies.
    Rate-limited like every /v1 call, never billed."""
    request_id = getattr(request.state, "trace_id", "")
    subject, _, _ = _caller(request)
    headers, limited = await _rate_limited(request, subject, request_id)
    if limited:
        return limited
    status, response = await _forward(request, "GET", "v1/studies")
    if not 200 <= status < 300:
        return _upstream_error(status, response, request_id, headers)
    return JSONResponse(response, status_code=status, headers={**headers, "X-Request-Id": request_id})
