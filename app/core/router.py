SERVICE_MAP = {
    "workbench": "http://workbench:8000",
    "tes": "http://tes:8081",
    "toolserver": "http://toolserver:9090",
    "model-registry": "http://model-registry:8095",
    "rag": "http://rag:8096",
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