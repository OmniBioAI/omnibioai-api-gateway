from fastapi import APIRouter, Request

# SSO Phase 2 PR8: a real, dedicated GET /auth/verify contract.
#
# PR7 found nginx-router.conf's `auth_request /internal/auth/verify`
# proxies to this exact path, but no such route existed -- requests fell
# through AuthMiddleware (which already 401s directly on a missing/invalid
# token, before any route handler runs) to the catch-all gateway route
# with an unmapped "auth" service, which returned an *incidental* HTTP 200
# with an irrelevant {"error": "unknown service"} body. auth_request only
# inspects the status code (nginx's own error_page synthesizes the actual
# 401 body seen by the client -- see nginx-router.conf's @cc_unauthorized/
# @devhub_unauthorized), so that accidental 200 happened to work, but a
# future change to the catch-all's default status code would have broken
# every nginx-gated route (/_svc/control, /rag/) silently, with nothing
# testing this path today.
#
# This route makes that contract explicit and tested instead of relying
# on cross-component accident.
router = APIRouter()


@router.get("/auth/verify")
async def auth_verify(request: Request):
    """Only ever reached with a valid, already-authenticated request --
    AuthMiddleware (app/middleware/auth.py) gates this path exactly like
    every other non-skip-listed route and returns 401 directly, before
    this handler runs, for a missing or invalid token. No second JWT
    validation path is introduced here; this handler only reads the
    identity AuthMiddleware already established on request.state.
    """
    user = request.state.user
    return {
        "authenticated": True,
        "user": {
            "id": user.get("user_id"),
            "roles": user.get("roles", []),
        },
    }
