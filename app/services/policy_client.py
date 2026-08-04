from typing import Optional

import httpx


class PolicyClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.http = httpx.AsyncClient(timeout=3)

    async def evaluate(
        self,
        user: dict,
        path: str,
        method: str,
        trace_id: str = "",
        required_permission: Optional[str] = None,
        service: Optional[str] = None,
    ) -> dict:
        # IAM Foundation gateway integration: when the caller (PolicyMiddleware)
        # already knows which IAM permission this path's target service
        # requires (SERVICE_MAP-derived -- see app/core/router.py), that
        # becomes `action` directly instead of the previous auto-derived
        # "post.samples.123"-style string, which stays as the fallback
        # for any path this gateway hasn't classified. The policy engine
        # -- not this client -- still makes the actual allow/deny call
        # either way; this only changes what context it's making that
        # call with.
        action = required_permission or f"{method.lower()}.{path.strip('/').replace('/', '.')}"
        payload = {
            "user_id": user.get("user_id", ""),
            "email": user.get("email", ""),
            "roles": user.get("roles", []),
            "permissions": user.get("permissions", []),
            "action": action,
            "resource": path,
            "service": service,
            "context": {"method": method, "path": path},
        }
        headers = {
            "X-Internal-Service": "gateway",
            "X-Trace-Id": trace_id,
            "X-User-Id": user.get("user_id", ""),
        }

        for attempt in range(2):
            try:
                res = await self.http.post(
                    f"{self.base_url}/policy/evaluate",
                    json=payload,
                    headers=headers,
                    timeout=3,
                )
                return res.json()
            except httpx.TimeoutException:
                if attempt == 0:
                    continue
                return {"allowed": False, "reason": "policy_timeout"}
            except Exception:
                return {"allowed": False, "reason": "policy_error"}

        return {"allowed": False, "reason": "policy_unavailable"}
