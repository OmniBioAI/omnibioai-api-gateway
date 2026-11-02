"""
OmniBioAI app.middleware.s2s.

Purpose:
    Defines TraceMiddleware HTTP request middleware.

Author:
    Manish Kumar <manish@omnibioai.org>
"""

import uuid
from app.core.public_routes import is_public_research_submission

from starlette.middleware.base import BaseHTTPMiddleware


class TraceMiddleware(BaseHTTPMiddleware):
    """
    Outermost middleware. Generates or propagates X-Trace-Id.
    Does NOT block external user requests — S2S validation is on downstream services.
    """

    async def dispatch(self, request, call_next):
        trace_id = request.headers.get("X-Trace-Id") or str(uuid.uuid4())
        if is_public_research_submission(request):
            # Never let anonymous input become personal content in trace logs.
            trace_id = str(uuid.uuid4())
        request.state.trace_id = trace_id

        response = await call_next(request)
        response.headers["X-Trace-Id"] = trace_id
        return response
