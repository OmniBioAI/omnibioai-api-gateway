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
