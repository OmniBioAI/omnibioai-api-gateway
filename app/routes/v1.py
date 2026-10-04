"""Public, versioned API: /v1/literature/*.

The authenticated catch-all (/{service}/{path}) forwards anything; this
router is the stable, billable contract external developers integrate
against. On top of the middleware chain (auth incl. omni_sk_ API keys,
policy, audit) every /v1 call gets:

- a token-bucket rate limit enforced both per caller and per organization
  (X-RateLimit-* headers, 429 + Retry-After) -- an organization can't
  multiply its effective limit by spreading requests across several API
  keys, and bursting a full minute's allowance at once no longer lets a
  caller squeeze in double that across one window boundary,
- a concurrency limit on in-flight /v1/literature/answers calls, per
  caller and per organization (429, independent of the rate limit above,
  which only bounds call frequency),
- an org-level quota check maintained by omnibioai-billing (402),
- optional Idempotency-Key replay, so a retried request is never run or
  billed twice,
- exactly one billable usage event per successful billable call -- except
  for an omni_sk_test_ key, which gets a canned response instead, never
  counted against quota or billed,
- one error shape: {"error": {"type", "message", "request_id"}}.

Request and response bodies of /v1/literature/answers are the frozen
public contract (app/services/literature_contract.py), translated
to/from omnibioai-rag's own POST /v1/query shape -- never passed
through unchanged, so RAG's internal response shape is free to change
independent of what external developers integrate against.
"""
import re
import time

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.core.config import Config
from app.core.router import resolve_service
from app.routes.gateway import build_upstream_headers, proxy
from app.services.literature_contract import (
    UnsupportedRequestError,
    build_public_answer,
    build_public_search,
    build_rag_query,
    build_rag_search_query,
    build_test_answer,
    build_test_search,
)
from app.services.v1_store import V1Store, request_fingerprint

router = APIRouter(prefix="/v1")
store = V1Store(Config.V1_REDIS_URL, Config.USAGE_REDIS_URL)

ANSWER_RESOURCE = "literature.answer"
SEARCH_RESOURCE = "literature.search"
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


async def _rate_limited(request: Request, subject: str, org_id: str, request_id: str):
    """limit is the caller's organization's plan-specific override
    (published by omnibioai-billing's gateway_quota_sync_service.py)
    when one is set, falling back to the configured global default --
    `is not None`, not `or`, since a plan-specific limit of exactly 0
    is a real (if unusual) value, not "unset".

    Enforced both per caller (subject -- an API key or a user session)
    and per organization (design audit gap #7: "it is enforced per
    caller/key, not both per key and per organisation") -- without the
    organization-wide counter, an organization holding N API keys could
    spread requests across them to multiply its effective limit by N,
    since each key previously got its own independent budget. Both
    counters share the same limit value; the request is rejected if
    either is exhausted, and the headers report whichever one is
    actually binding (the smaller remaining count) so the caller can
    tell which budget they're hitting.
    """
    org_limit = await store.rate_limit_for_org(org_id) if org_id else None
    limit = org_limit if org_limit is not None else Config.V1_RATE_LIMIT_PER_MINUTE

    key_allowed, key_remaining, key_reset = await store.hit_rate_limit(subject, limit)
    if org_id:
        org_allowed, org_remaining, org_reset = await store.hit_rate_limit(f"org:{org_id}", limit)
    else:
        # No organization on this identity at all -- shouldn't normally
        # happen for an authenticated /v1 caller, but fails open here
        # (only the per-key check applies) rather than crashing on it.
        org_allowed, org_remaining, org_reset = True, key_remaining, key_reset

    allowed = key_allowed and org_allowed
    remaining, reset = (org_remaining, org_reset) if org_remaining <= key_remaining else (key_remaining, key_reset)

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


async def _acquire_concurrency_slots(org_id: str, subject: str, limit: int) -> bool:
    """Both the subject's and the organization's in-flight counters must
    have a free slot for the duration of one /v1/literature/answers call
    -- if the organization's is full, a key that's never made a request
    of its own must still be blocked, the same per-key-and-per-org
    pairing _rate_limited already enforces for request frequency."""
    if not await store.acquire_concurrency_slot(subject, limit):
        return False
    if org_id and not await store.acquire_concurrency_slot(f"org:{org_id}", limit):
        await store.release_concurrency_slot(subject)
        return False
    return True


async def _release_concurrency_slots(org_id: str, subject: str) -> None:
    await store.release_concurrency_slot(subject)
    if org_id:
        await store.release_concurrency_slot(f"org:{org_id}")


async def _forward_to(service: str, request: Request, method: str, path: str, body=None):
    url = f"{resolve_service(service)}/{path}"
    if request.url.query:
        url = f"{url}?{request.url.query}"
    return await proxy.forward(url=url, method=method, headers=build_upstream_headers(request), body=body)


async def _forward(request: Request, method: str, path: str, body=None):
    return await _forward_to("rag", request, method, path, body)


def _upstream_error(status: int, response, request_id: str, headers: dict):
    if status >= 500:
        return _error(502 if status == 500 else status, "upstream_error",
                      "The literature service failed to answer. You were not charged.", request_id, headers)
    return _error(status, "invalid_request" if status in (400, 422) else "request_failed",
                  "The literature service rejected the request.", request_id, headers, detail=response)


async def _handle_billable_literature_call(
    request: Request, *, resource: str, build_rag_body, build_public_response, build_test_response,
    quota_exceeded_message: str, max_concurrent_answers: int | None = None,
):
    """Shared lifecycle for every billable /v1/literature/* call
    (currently /answers and /search): auth'd-org check, contract
    translation, rate limit, idempotency replay, quota check, forward to
    RAG, response translation, usage emission, quota consumption. The two
    callers differ only in which resource they bill, how they translate
    their request/response, and their quota-exceeded wording -- every
    other step (in particular the idempotency/quota/usage sequencing)
    must stay identical between them, so it lives here once rather than
    as two copies that could silently drift apart.

    An omni_sk_test_ key (identity.test_mode) short-circuits to
    build_test_response's canned answer -- real rate limiting still
    applies (abuse protection the gateway itself needs regardless of
    whether a call is "real"), but quota, the concurrency cap, the real
    RAG call, and usage emission are all skipped: a test key must never
    consume real org quota, real RAG capacity, or be billed.
    """
    request_id = getattr(request.state, "trace_id", "")
    subject, org_id, user_id = _caller(request)
    identity = getattr(request.state, "identity", None) or {}
    test_mode = bool(identity.get("test_mode"))
    if not org_id:
        return _error(403, "organization_required",
                      "This API is billed to an organization; your account has none.", request_id)

    try:
        body = await request.json()
    except Exception:
        return _error(400, "invalid_request", "Request body must be JSON.", request_id)

    try:
        rag_body = build_rag_body(body)
    except UnsupportedRequestError as exc:
        return _error(400, "unsupported_request", exc.message, request_id, detail={"field": exc.field})

    headers, limited = await _rate_limited(request, subject, org_id, request_id)
    if limited:
        return limited

    idempotency_key = request.headers.get("Idempotency-Key")
    # Fingerprinted on the public request body the caller actually sent
    # -- not the translated RAG body -- so "same Idempotency-Key, same
    # request" is judged by the contract the caller integrates against.
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

    # A test key never touches real RAG capacity, so it never needs (or
    # holds) a concurrency slot -- acquiring one here, only to release it
    # a few lines down having done no real work, would just be unearned
    # contention against real callers sharing the same key/org budget.
    acquire_concurrency = max_concurrent_answers is not None and not test_mode
    if acquire_concurrency:
        if not await _acquire_concurrency_slots(org_id, subject, max_concurrent_answers):
            if idempotency_key is not None:
                await store.idempotency_finish(subject, idempotency_key, fingerprint, 429, None)
            return _error(
                429, "concurrency_limit_exceeded",
                f"More than {max_concurrent_answers} concurrent requests for this key or organization.",
                request_id, headers,
            )

    try:
        if test_mode:
            public_response = build_test_response(domain=body.get("domain"), request_id=request_id, latency_ms=0)
            if idempotency_key is not None:
                await store.idempotency_finish(subject, idempotency_key, fingerprint, 200, public_response)
            # No reserve_quota, no RAG forward, no emit_usage: a test key
            # consumes no real quota, calls no real upstream, and is never
            # billed -- that is the entire point of test mode.
            return JSONResponse(public_response, status_code=200, headers={**headers, "X-Request-Id": request_id})

        # Atomic reserve-before-work: decrements the quota counter now, not
        # after the upstream call succeeds, so concurrent requests can
        # never all observe "quota available" and all succeed (see
        # V1Store.reserve_quota's own docstring for why the old check-
        # then-later-decrement pair could overrun a near-zero quota).
        if not await store.reserve_quota(org_id, resource):
            if idempotency_key is not None:
                await store.idempotency_finish(subject, idempotency_key, fingerprint, 402, None)
            return _error(402, "quota_exceeded", quota_exceeded_message, request_id, headers)

        started = time.monotonic()
        status, response = await _forward(request, "POST", "v1/query", rag_body)
        latency_ms = round((time.monotonic() - started) * 1000)

        if not 200 <= status < 300:
            # The reservation above assumed this call would succeed and be
            # billed; it didn't, so the unit must be given back.
            await store.release_quota(org_id, resource)
            if idempotency_key is not None:
                await store.idempotency_finish(subject, idempotency_key, fingerprint, status, response)
            return _upstream_error(status, response, request_id, headers)

        public_response = build_public_response(
            response, domain=body.get("domain"), request_id=request_id, latency_ms=latency_ms,
        )
        if idempotency_key is not None:
            await store.idempotency_finish(subject, idempotency_key, fingerprint, status, public_response)

        await store.emit_usage(
            org_id=org_id,
            user_id=user_id,
            resource=resource,
            trace_id=request_id,
            dedup_key=f"{subject}:{idempotency_key}" if idempotency_key else request_id,
            metadata={
                "request_id": request_id,
                "client_id": identity.get("client_id"),
                "token_type": identity.get("token_type"),
                "idempotency_key_sha256": request_fingerprint(idempotency_key) if idempotency_key else None,
            },
        )
        return JSONResponse(public_response, status_code=status, headers={**headers, "X-Request-Id": request_id})
    finally:
        # Released regardless of how the try block above exited (a quota
        # denial, an upstream error, or success) -- a slot held by a
        # request that's already finished answering must never count
        # against the next one.
        if acquire_concurrency:
            await _release_concurrency_slots(org_id, subject)


@router.post("/literature/answers")
async def literature_answers(request: Request):
    return await _handle_billable_literature_call(
        request,
        resource=ANSWER_RESOURCE,
        build_rag_body=build_rag_query,
        build_public_response=build_public_answer,
        build_test_response=build_test_answer,
        quota_exceeded_message="Your organization has used its included answers. "
                                "Add a payment method or upgrade the plan.",
        max_concurrent_answers=Config.V1_MAX_CONCURRENT_ANSWERS,
    )


@router.post("/literature/search")
async def literature_search(request: Request):
    """Billable unit: 1 search (see the design doc's pricing table --
    priced around 1/10th of an answer). Retrieval only: never invokes an
    LLM, via RAG's mode="search" (app/services/literature_contract.py's
    build_rag_search_query sets it)."""
    return await _handle_billable_literature_call(
        request,
        resource=SEARCH_RESOURCE,
        build_rag_body=build_rag_search_query,
        build_public_response=build_public_search,
        build_test_response=build_test_search,
        quota_exceeded_message="Your organization has used its included searches. "
                                "Add a payment method or upgrade the plan.",
    )


@router.get("/literature/studies")
async def literature_studies(request: Request):
    """Free: the queryable studies/domains, from omnibioai-rag GET /v1/studies.
    Rate-limited like every /v1 call, never billed."""
    request_id = getattr(request.state, "trace_id", "")
    subject, org_id, _ = _caller(request)
    headers, limited = await _rate_limited(request, subject, org_id, request_id)
    if limited:
        return limited
    status, response = await _forward(request, "GET", "v1/studies")
    if not 200 <= status < 300:
        return _upstream_error(status, response, request_id, headers)
    return JSONResponse(response, status_code=status, headers={**headers, "X-Request-Id": request_id})


@router.get("/literature/domains")
async def literature_domains(request: Request):
    """Free: the queryable research domains, under the frozen public
    name the design doc uses ("domain", not RAG's internal "study").
    Same underlying data as /literature/studies above (kept as-is for
    backward compatibility) via the same omnibioai-rag GET /v1/studies
    call, reshaped to the public contract. Rate-limited like every /v1
    call, never billed."""
    request_id = getattr(request.state, "trace_id", "")
    subject, org_id, _ = _caller(request)
    headers, limited = await _rate_limited(request, subject, org_id, request_id)
    if limited:
        return limited
    status, response = await _forward(request, "GET", "v1/studies")
    if not 200 <= status < 300:
        return _upstream_error(status, response, request_id, headers)
    domains = [
        {"name": s.get("name"), "abstract_count": s.get("abstract_count")}
        for s in (response.get("studies") or [])
    ]
    return JSONResponse({"domains": domains}, status_code=status, headers={**headers, "X-Request-Id": request_id})


@router.get("/usage")
async def literature_usage(request: Request):
    """Free: the caller's organization's included/used/remaining units
    for the current billing period, from omnibioai-billing's existing
    GET /billing/organizations/{id}/subscription/usage-limits -- the
    gateway's first synchronous call into billing-service (see
    app/core/router.py's SERVICE_MAP/SERVICE_PERMISSION_MAP entries,
    gated on usage.read). Rate-limited like every /v1 call, never
    billed.

    Estimated charge in dollars (also mentioned in the design doc) is
    deliberately omitted: that needs billing's cost-summary endpoint and
    its own start_date/end_date period math, which this does not yet do.
    Reporting a wrong number would be worse than omitting it -- the same
    principle app/services/literature_contract.py applies to token
    counts.
    """
    request_id = getattr(request.state, "trace_id", "")
    subject, org_id, _ = _caller(request)
    if not org_id:
        return _error(403, "organization_required",
                      "This API is billed to an organization; your account has none.", request_id)

    headers, limited = await _rate_limited(request, subject, org_id, request_id)
    if limited:
        return limited

    status, response = await _forward_to(
        "billing", request, "GET", f"billing/organizations/{org_id}/subscription/usage-limits",
    )
    if status == 404:
        return _error(404, "no_active_plan", "Your organization has no active billing plan.", request_id, headers)
    if not 200 <= status < 300:
        return _error(502 if status >= 500 else status, "upstream_error",
                      "The billing service failed to report usage.", request_id, headers,
                      detail=response if status < 500 else None)

    usage = [
        {
            "resource": item.get("resource"),
            "unit": item.get("unit"),
            "period": item.get("period"),
            "included": item.get("included"),
            "used": item.get("used"),
            "remaining": item.get("remaining"),
        }
        for item in (response.get("limits") or [])
    ]
    return JSONResponse(
        {"plan": response.get("plan_name"), "as_of": response.get("as_of"), "usage": usage},
        status_code=200, headers={**headers, "X-Request-Id": request_id},
    )


@router.get("/models")
async def literature_models(request: Request):
    """Free: the model catalog -- answer/embedding models currently
    served, with source and price. Rate-limited like every /v1 call,
    never billed. No upstream call: there is exactly one model path
    today, RAG's own GPU-hosted default (see the design's "largest
    gaps" #4 -- Claude/OpenAI routing and bring-your-own-key do not
    exist yet, and build_rag_query already rejects any request that
    would need one).

    price is null, not a placeholder dollar figure: the design doc's own
    pricing section says to measure real GPU cost per answer first
    (milestone M0, 1,000 representative questions) before setting
    prices, and that measurement has not been run. The model actually
    used for a given answer is already reported per-call in
    /v1/literature/answers' response (its `model` field is the real
    value RAG used; "default" here is the stable identifier a caller
    passes back as this endpoint's own `model` request field).
    """
    request_id = getattr(request.state, "trace_id", "")
    subject, org_id, _ = _caller(request)
    headers, limited = await _rate_limited(request, subject, org_id, request_id)
    if limited:
        return limited
    models = [
        {"model": "default", "source": "omnibioai_gpu", "billed_by": "query", "price": None},
    ]
    return JSONResponse({"models": models}, status_code=200, headers={**headers, "X-Request-Id": request_id})


# ---------------------------------------------------------------------------
# M15 (design audit gap #4, first slice of BYOK): proxies into
# omnibioai-auth's own PUT/GET/DELETE /orgs/{org_id}/provider-keys(/
# {provider}) (M14's storage service) -- never implemented here, just
# forwarded, the same pattern GET /v1/usage above already uses for
# omnibioai-billing. Free (not a billable /v1/literature/* call); still
# rate-limited like every other /v1 route.
# ---------------------------------------------------------------------------


def _provider_key_error(status: int, response, request_id: str, headers: dict):
    if status >= 500:
        return _error(502, "upstream_error",
                      "The identity service failed to process this request.", request_id, headers)
    if status == 403:
        return _error(403, "forbidden",
                       "You do not have permission to manage this organization's provider keys.",
                       request_id, headers)
    if status == 404:
        return _error(404, "not_found", "No key is configured for that provider.", request_id, headers)
    return _error(status, "invalid_request", "The identity service rejected the request.",
                  request_id, headers, detail=response)


@router.put("/provider-keys/{provider}")
async def set_provider_key(request: Request, provider: str):
    """Store this organization's own Claude/OpenAI key, encrypted at
    rest by omnibioai-auth. Storage only -- nothing yet routes a real
    /v1/literature/answers call through it (design audit gap #4's
    remaining bullets)."""
    request_id = getattr(request.state, "trace_id", "")
    subject, org_id, _ = _caller(request)
    if not org_id:
        return _error(403, "organization_required",
                      "This API is billed to an organization; your account has none.", request_id)
    try:
        body = await request.json()
    except Exception:
        return _error(400, "invalid_request", "Request body must be JSON.", request_id)

    headers, limited = await _rate_limited(request, subject, org_id, request_id)
    if limited:
        return limited

    status, response = await _forward_to("auth", request, "PUT", f"orgs/{org_id}/provider-keys/{provider}", body)
    if not 200 <= status < 300:
        return _provider_key_error(status, response, request_id, headers)
    return JSONResponse(response, status_code=status, headers={**headers, "X-Request-Id": request_id})


@router.get("/provider-keys")
async def get_provider_key(request: Request):
    """Whether (and which provider's) key is configured -- never the
    key itself, the same write-only contract omnibioai-auth's own
    endpoint already enforces."""
    request_id = getattr(request.state, "trace_id", "")
    subject, org_id, _ = _caller(request)
    if not org_id:
        return _error(403, "organization_required",
                      "This API is billed to an organization; your account has none.", request_id)

    headers, limited = await _rate_limited(request, subject, org_id, request_id)
    if limited:
        return limited

    status, response = await _forward_to("auth", request, "GET", f"orgs/{org_id}/provider-keys")
    if not 200 <= status < 300:
        return _provider_key_error(status, response, request_id, headers)
    return JSONResponse(response, status_code=status, headers={**headers, "X-Request-Id": request_id})


@router.delete("/provider-keys/{provider}")
async def delete_provider_key(request: Request, provider: str):
    request_id = getattr(request.state, "trace_id", "")
    subject, org_id, _ = _caller(request)
    if not org_id:
        return _error(403, "organization_required",
                      "This API is billed to an organization; your account has none.", request_id)

    headers, limited = await _rate_limited(request, subject, org_id, request_id)
    if limited:
        return limited

    status, response = await _forward_to("auth", request, "DELETE", f"orgs/{org_id}/provider-keys/{provider}")
    if not 200 <= status < 300:
        return _provider_key_error(status, response, request_id, headers)
    return JSONResponse(response, status_code=status, headers={**headers, "X-Request-Id": request_id})
