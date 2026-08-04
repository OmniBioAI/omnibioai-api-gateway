"""IAM Foundation gateway integration: a reusable, permission-based
FastAPI dependency for any route this gateway defines natively (e.g.
/auth/verify, and any future typed route) -- Step 4's require_permission.

Deliberately NOT wired into the catch-all proxy route
(app/routes/gateway.py): PolicyMiddleware already makes the authorization
decision for every proxied request via the remote policy engine, now
enriched with the gateway-derived required permission (see
app/core/router.py::resolve_required_permission and
app/middleware/policy.py). Adding a second, independent 403 here for the
same proxied paths would duplicate that decision instead of feeding it --
exactly what this integration is meant to avoid. This dependency exists
for routes that have no policy-engine evaluation at all.
"""
from __future__ import annotations

from fastapi import HTTPException, Request


def require_permission(permission: str):
    """Returns a FastAPI dependency that 403s unless `permission` is
    present in request.state.identity["permissions"] -- never role-based,
    never username-based. Requires AuthMiddleware to have already run
    (request.state.identity set); routes using this dependency must not
    be in any middleware's skip-list."""

    def _require_permission(request: Request) -> dict:
        identity = getattr(request.state, "identity", None)
        if identity is None:
            raise HTTPException(401, "Missing or invalid identity")
        if permission not in (identity.get("permissions") or []):
            raise HTTPException(403, "Insufficient permissions")
        return identity

    return _require_permission
