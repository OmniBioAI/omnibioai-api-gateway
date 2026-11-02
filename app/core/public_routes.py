"""Narrow anonymous ingress contract shared by all Gateway gates."""

def is_public_research_submission(request):
    return request.url.path == "/api/v1/research-inquiries" and request.method in {"POST", "OPTIONS"}
