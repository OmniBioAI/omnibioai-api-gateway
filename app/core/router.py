SERVICE_MAP = {
    "workbench": "http://workbench:8000",
    "tes": "http://tes:8081",
    "toolserver": "http://toolserver:9090",
    "model-registry": "http://model-registry:8095",
    "rag": "http://rag:8096",
    # ServiceNow Enterprise Integration: omnibioai-servicenow, a new
    # backend service (not embedded in Control Center's proxy layer --
    # every routes_*_proxy.py in that repo relays to a service that
    # already does its own independent authorization, and this one is no
    # different) that owns the OAuth 2.0 client-credentials connection to
    # ServiceNow and the incident CRUD surface. Same shape as every other
    # SERVICE_MAP entry: this gateway proxies to it, it does not implement
    # any ServiceNow logic itself.
    "servicenow": "http://servicenow:8097",
    # Public API v1 ("M1": GET /v1/usage): the gateway proxies this one
    # read-only call into omnibioai-billing's existing
    # GET /billing/organizations/{id}/subscription/usage-limits, reusing
    # the same build_upstream_headers()-forwarded bearer token every
    # other SERVICE_MAP entry relies on -- billing-service independently
    # verifies it against the same shared-platform JWT secret (see its
    # app/core/iam.py::_verify_caller), exactly like omnibioai-rag does
    # for the "rag" entry above. See SERVICE_PERMISSION_MAP below for the
    # permission this requires.
    "billing": "http://billing-service:8005",
}


def resolve_service(service: str) -> str | None:
    return SERVICE_MAP.get(service)


# IAM Foundation gateway integration: the IAM permission each downstream
# service requires, keyed to this gateway's actual SERVICE_MAP -- not the
# generic /workflow, /services, /models, /datasets path groups a template
# spec for this integration described, which don't correspond to any real
# route here. All three permission names (workflow.execute, model.use,
# dataset.read) are already registered in omnibioai-auth's Permission
# Registry (app/core/permission_names.py) as "reserved -- not yet enforced
# by any route"; this is their first real consumer.
#
# workbench/tes/toolserver all map to workflow.execute: workbench is the
# workflow/job submission platform, and tes/toolserver are its HPC
# execution backends (also independently quota-gated by HPCMiddleware,
# a separate concern from permission checking). There is no registered
# "services.*" permission and none is introduced here -- see this PR's
# report for why.
SERVICE_PERMISSION_MAP = {
    "workbench": "workflow.execute",
    "tes": "workflow.execute",
    "toolserver": "workflow.execute",
    "model-registry": "model.use",
    "rag": "dataset.read",
    # Coarse, service-level gate only -- same "one permission per service"
    # granularity every other SERVICE_MAP entry gets here, gating whether
    # the policy engine lets a request reach omnibioai-servicenow at all.
    # That service independently re-verifies the JWT and enforces the
    # finer read-vs-write distinction itself (servicenow_incident.read on
    # GET routes, servicenow_incident.write on the mutating ones) -- the
    # same layered "gateway-level coarse gate + service-level independent,
    # finer check" pattern omnibioai-rag's dataset.read/app/api/iam.py
    # already established, not a new authorization model.
    "servicenow": "servicenow_incident.read",
    # Public API v1 (GET /v1/usage): omnibioai-auth's Permission Registry
    # already has "usage.read" registered as "reserved -- not yet
    # enforced by any route" -- the exact same state dataset.read/
    # model.use/workflow.execute were in before this gateway's IAM
    # Foundation integration made them real. This is usage.read's first
    # real consumer.
    "billing": "usage.read",
}


def resolve_required_permission(service: str) -> str | None:
    """The IAM permission `service` requires, or None for an unmapped
    service (e.g. an unknown service -- resolve_service() already returns
    None for that case and the gateway route responds accordingly --  or
    a real but not-yet-classified one). None means "no gateway-derived
    permission context to add"; it is not itself an allow/deny signal --
    PolicyMiddleware's remote policy-engine call remains the actual
    authorization decision either way."""
    return SERVICE_PERMISSION_MAP.get(service)

# Public /v1 API (app/routes/v1.py): which downstream service, and so which
# IAM permission, each /v1/<area>/ path stands for. PolicyMiddleware uses
# this so /v1/literature/* is authorized exactly like the rag service.
V1_SERVICE_MAP = {
    "literature": "rag",
}


def service_for_path(path: str) -> str:
    """The SERVICE_MAP key a request path targets: the first path segment,
    or for /v1/<area>/... the service V1_SERVICE_MAP maps <area> to."""
    parts = path.strip("/").split("/")
    if parts[0] == "v1" and len(parts) > 1 and parts[1] in V1_SERVICE_MAP:
        return V1_SERVICE_MAP[parts[1]]
    return parts[0]
