import os


class Config:
    IAM_URL = os.getenv("IAM_URL", "http://omnibioai-auth:8000")
    # omnibioai-iam-client's AsyncIAMClient derives its own JWKS URL as
    # f"{base_url}/.well-known/jwks.json" internally (app/services/
    # iam_client.py's _shared instance) rather than taking one as a
    # constructor argument -- IAM_JWKS_URL exists here only as the
    # documented, discoverable value operators expect per this service's
    # deployment contract, and defaults to exactly what the shared client
    # already computes from IAM_URL.
    IAM_JWKS_URL = os.getenv("IAM_JWKS_URL", f"{IAM_URL}/.well-known/jwks.json")
    # Not yet enforced: omnibioai-iam-client's decode_token() verifies
    # signature/expiry only, and omnibioai-auth issues no `aud`/`iss`
    # claims on any token today, so there is nothing yet to validate
    # these against. Wired here so the config contract exists ahead of
    # that support landing in both places.
    IAM_AUDIENCE = os.getenv("IAM_AUDIENCE", "")
    IAM_ISSUER = os.getenv("IAM_ISSUER", "")
    POLICY_URL = os.getenv("POLICY_URL", "http://omnibioai-policy-engine:8001")
    HPC_URL = os.getenv("HPC_URL", "http://omnibioai-hpc-policy-engine:8002")
    AUDIT_REDIS = os.getenv("AUDIT_REDIS", "redis://redis:6379")
    REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379")
    JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret")
    SERVICE_SECRET = os.getenv("GATEWAY_SECRET", "dev-secret")
    ROUTE_TIMEOUT = int(os.getenv("ROUTE_TIMEOUT", "15"))
    # omni_sk_ API keys: the gateway trades a key for a short-lived access
    # token at omnibioai-auth's POST /auth/api-keys/exchange, which only
    # accepts calls carrying this shared secret. Empty = API keys rejected.
    API_KEY_EXCHANGE_SECRET = os.getenv("API_KEY_EXCHANGE_SECRET", "")
    # Upper bound on how long one exchange is reused; the minted token's
    # own expiry (minus a safety margin) caps it further.
    API_KEY_CACHE_TTL = int(os.getenv("API_KEY_CACHE_TTL", "60"))

    # Public /v1 API (app/routes/v1.py). Rate-limit, idempotency and quota
    # state lives under gateway:v1:* in the Redis at V1_REDIS_URL, which
    # needs its own ACL user (incr/expire/get/set/del/decr on gateway:v1:*).
    # Unset = an in-process store: correct for a single gateway replica
    # (Studio runs one), lost on restart, and quota counters written by
    # omnibioai-billing are then not visible.
    V1_REDIS_URL = os.getenv("V1_REDIS_URL", "")
    V1_RATE_LIMIT_PER_MINUTE = int(os.getenv("V1_RATE_LIMIT_PER_MINUTE", "60"))
    V1_IDEMPOTENCY_TTL = int(os.getenv("V1_IDEMPOTENCY_TTL", "86400"))
    # Billable usage goes to the same usage:events stream every other
    # producer writes (omnibioai-usage-client wire format), consumed by
    # omnibioai-billing.
    USAGE_REDIS_URL = os.getenv("USAGE_REDIS_URL", REDIS_URL)
    USAGE_STREAM = os.getenv("USAGE_STREAM", "usage:events")
    # A billable usage event is on the hot path of a successful, already-
    # answered request -- V1Store.emit_usage must never raise back into
    # the route. Historically it just swallowed an XADD failure and
    # returned False, discarded by the caller: a real Redis outage at
    # exactly the wrong moment meant a successful answer was returned
    # (and the caller charged nothing) while its usage event was lost
    # forever. app/services/outbox.py gives that failure a second chance:
    # a local SQLite file, drained back into Redis on a later request
    # once it recovers. A lost event must never become an overcharge, so
    # this only ever adds a delayed write, never a duplicate billing path
    # (drain uses the event's own deterministic event_id, same dedup
    # omnibioai-billing's consumer already enforces).
    USAGE_OUTBOX_PATH = os.getenv("USAGE_OUTBOX_PATH", "/tmp/gateway_usage_outbox.db")
