import json
from typing import Callable, Optional

import httpx
import redis.asyncio as aioredis
from iam_client import AsyncIAMClient as _SharedIAMClient

from app.core.config import Config


class IAMClient:
    """Gateway's IAM integration point. Token *verification* itself
    (RS256/JWKS signature check, HS256 fallback, expiration) is delegated
    to the shared omnibioai-iam-client package (`self._shared`) -- see
    validate() below -- rather than reimplemented here, closing the gap
    the old version of this class had: it trusted the remote
    /auth/validate call for signature validity too, with no local check
    of its own at all.

    The cache-first + remote-authoritative-revocation flow around that
    call, and this class's public method names (validate/evict/
    subscribe_invalidation), are deliberately kept as they were rather
    than replaced by the shared package's own get_user()/evict_cache()/
    subscribe_invalidation(): that package's Redis usage is a *synchronous*
    redis-py client called from async methods (including a plain `for`
    loop wrapped in `async for` in its subscribe_invalidation) -- swapping
    to it wholesale would block this service's event loop on every cache
    hit and break the pub/sub invalidation listener outright. Using the
    shared package only for the piece it does correctly and this class
    didn't do at all (decode_token's signature/expiry verification) avoids
    that bug entirely while still closing the real gap. Flagged in this
    PR's report as a follow-up for the shared package itself.
    """

    def __init__(self, base_url: str, redis_url: str):
        self.base_url = base_url.rstrip("/")
        self.redis = aioredis.from_url(redis_url, decode_responses=True)
        self.http = httpx.AsyncClient(timeout=3)
        # Only ever used for its decode_token() -- never touches its own
        # (synchronous) Redis connection or makes an /auth/validate call
        # of its own; this class's existing cache + remote-validate flow
        # below remains the single path for those.
        self._shared = _SharedIAMClient(base_url, redis_url)

    # ------------------------------------------------------------------
    # Cache helpers  (key: gateway:iam:{token}, TTL 5 min)
    #
    # Prefixed, not the shared package's own bare "iam:{token}" -- this
    # class is its own independent, hand-rolled cache (see class
    # docstring for why: the shared package's Redis usage is synchronous
    # and would block this service's event loop), but it was writing to
    # the *same* Redis instance and the *same* unprefixed key every other
    # IAM-integrated service (billing, rag, model-registry -- see the
    # str(org_id) comment above) also reads/writes via the shared
    # package's own AsyncIAMClient.get_user()/set_cache(). Two
    # independent cache implementations racing on one shared key means
    # whichever service validates a given token first dictates the
    # shape every other service's read has to survive -- this is
    # exactly the mechanism the org_id-as-str fix above already had to
    # work around once, and omnibioai-tes's own equivalent hand-rolled
    # cache (security/iam.py there, now "tes:iam:") hit the same
    # collision independently, reproduced live as a pydantic
    # ValidationError on the workflow-bundles side. This prefix removes
    # gateway from that shared key entirely, on the same principle.
    # ------------------------------------------------------------------
    _CACHE_PREFIX = "gateway:iam:"

    async def _get_cached(self, token: str) -> Optional[dict]:
        try:
            raw = await self.redis.get(f"{self._CACHE_PREFIX}{token}")
            return json.loads(raw) if raw else None
        except Exception:
            return None

    async def _set_cached(self, token: str, user: dict, ttl: int = 300):
        try:
            await self.redis.setex(f"{self._CACHE_PREFIX}{token}", ttl, json.dumps(user))
        except Exception:
            pass

    async def evict(self, token: str):
        try:
            await self.redis.delete(f"{self._CACHE_PREFIX}{token}")
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Validate token: cache-first, then remote auth service (1 retry)
    # ------------------------------------------------------------------
    async def validate(self, token: str) -> Optional[dict]:
        cached = await self._get_cached(token)
        if cached:
            return cached

        # RS256/JWKS-or-HS256 signature + expiry verification, dispatched
        # by the token's own `alg` header -- delegated entirely to the
        # shared package rather than reimplemented here. Rejects fast,
        # without ever reaching the remote call below, on a bad
        # signature, expired token, malformed token, or (RS256 only) an
        # unresolvable JWKS key -- including on a JWKS-endpoint fetch
        # failure, which fails closed here by design (same choice
        # omnibioai-control-center's core/jwt_verify.py already made for
        # the identical case) rather than falling through to a path that
        # never checked the signature at all. A token that passes this
        # still isn't authoritatively confirmed -- revocation status
        # only lives at the auth service -- so the remote call below
        # always still runs for one that does.
        try:
            await self._shared.decode_token(token, secret=Config.JWT_SECRET)
        except Exception:
            return None

        for attempt in range(2):
            try:
                res = await self.http.post(
                    f"{self.base_url}/auth/validate",
                    json={"token": token},
                    timeout=3,
                )
                data = res.json()

                if not data.get("valid"):
                    await self.evict(token)
                    return None

                user = {
                    "user_id": str(data["user_id"]),
                    "email": data.get("email", ""),
                    "roles": data.get("roles", []),
                    "permissions": data.get("permissions", []),
                    # Phase 1 PR3 -- additive. schema_version distinguishes
                    # "this response predates org context" (absent/1) from
                    # "org_id is genuinely null because this user has no
                    # org membership yet" (2, org_id=None) -- both are
                    # valid states, not errors. A cache entry written by a
                    # pre-PR3 gateway process (before this field existed)
                    # is read back the same way via _get_cached's raw
                    # json.loads -- callers reading .get("org_id") on that
                    # dict get None either way, so no special-case handling
                    # is needed for old cache entries, only for the shape
                    # of what a *new* validate() call writes.
                    #
                    # PR14.5D: str(), not the raw value -- /auth/validate's
                    # JSON returns org_id as an int (its own DB primary
                    # key), and this cache lives under the same `iam:
                    # {token}` Redis key namespace the shared omnibioai-
                    # iam-client package's own AsyncIAMClient reads from
                    # (every other IAM-integrated service -- billing, rag,
                    # model-registry -- uses that package, not this one).
                    # That package's UserContext pydantic model declares
                    # org_id: Optional[str], strict in pydantic v2 (no
                    # int->str coercion) -- an int here means any of those
                    # services' first read of a token gateway already
                    # cached raises a ValidationError, silently swallowed
                    # by their own broad `except Exception: user = None`,
                    # misreporting a perfectly valid token as invalid.
                    # Reproduced live: billing-service returning 401
                    # "Invalid, expired, or revoked token" for a token
                    # that worked fine called directly, only after it had
                    # first passed through nginx's auth_request gate
                    # (which calls this validate() and populates the
                    # shared cache). validate_remote() in the shared
                    # package itself already does this identical cast for
                    # its own cache writes -- this brings gateway's
                    # independent cache-write (see this class's docstring
                    # for why it has one) in line with that, instead of
                    # leaving the two silently incompatible.
                    "org_id": str(data["org_id"]) if data.get("org_id") is not None else None,
                    "org_role": data.get("org_role", []),
                    "schema_version": data.get("schema_version", 1),
                    "valid": True,
                }
                await self._set_cached(token, user)
                return user

            except httpx.TimeoutException:
                if attempt == 0:
                    continue
                return None
            except Exception:
                return None

        return None

    # ------------------------------------------------------------------
    # Redis Pub/Sub — subscribe to "policy:invalidate" channel
    # on_invalidate(user_id, token) is called for each message
    # ------------------------------------------------------------------
    async def subscribe_invalidation(self, on_invalidate: Callable):
        pubsub = self.redis.pubsub()
        await pubsub.subscribe("policy:invalidate")
        async for message in pubsub.listen():
            if message["type"] == "message":
                try:
                    data = json.loads(message["data"])
                    await on_invalidate(
                        data.get("user_id", ""),
                        data.get("token", ""),
                    )
                except Exception:
                    pass
