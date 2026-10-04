"""Translates between the frozen public /v1/literature/answers contract
(the Public API v1 design) and omnibioai-rag's internal POST /v1/query
request/response shape. Request and response bodies of
/v1/literature/answers used to be passed through to/from RAG unchanged
-- real external developers integrate against the stable public shape
below, not RAG's own internal one, which is free to change independent
of this contract.

Deliberately rejects (rather than silently ignoring or mis-answering)
every request field this gateway cannot yet honor: model routing,
bring-your-own-key, and streaming are not implemented (see the design's
"largest gaps" #4) -- a caller who asks for Claude and silently gets the
default model, or asks to stream and silently gets one JSON blob, would
be a worse failure than a clear 400.
"""
import uuid


class UnsupportedRequestError(Exception):
    """Raised for a well-formed request this gateway cannot yet honor.
    `field` names which request field caused it, for the error envelope's
    `detail`."""

    def __init__(self, field: str, message: str):
        self.field = field
        self.message = message
        super().__init__(message)


# The only two spellings "no model override" takes today: the field is
# absent/None, or the caller explicitly names RAG's actual current
# default via this sentinel-free "default" shorthand.
_NO_MODEL_OVERRIDE = (None, "", "default")

# M16 (design audit gap #4): the only two models BYOK routing can select
# -- there is no platform-wide Claude/OpenAI key, only an organization's
# own (see app/routes/v1.py's reveal-and-forward step), so either of
# these requires use_own_key: true. Any other non-default value is a
# model this gateway still has no route for at all.
_BYOK_MODELS = ("claude", "openai")


def build_rag_query(body: dict) -> dict:
    """Translate a public /v1/literature/answers request body into RAG's
    POST /v1/query body. Raises UnsupportedRequestError for a field this
    gateway cannot yet honor.

    model="claude"/"openai" with use_own_key=true passes `model` through
    to RAG's own body (see QueryRequest in omnibioai-rag's
    app/api/server.py) -- app/routes/v1.py is what actually resolves and
    attaches the organization's decrypted key before forwarding; this
    function only validates the request shape, never touches a key.
    """
    if not isinstance(body, dict):
        raise UnsupportedRequestError("body", "Request body must be a JSON object.")

    question = body.get("question")
    if not isinstance(question, str) or not question.strip():
        raise UnsupportedRequestError("question", "\"question\" is required and must be a non-empty string.")

    model = body.get("model")
    use_own_key = bool(body.get("use_own_key"))
    if model not in _NO_MODEL_OVERRIDE and model not in _BYOK_MODELS:
        raise UnsupportedRequestError(
            "model", f"Model {model!r} is not yet supported; omit this field to use the default model.",
        )
    if model in _BYOK_MODELS and not use_own_key:
        raise UnsupportedRequestError(
            "use_own_key",
            f"Routing to {model!r} requires use_own_key: true -- there is no platform-wide key for this provider.",
        )
    if use_own_key and model not in _BYOK_MODELS:
        raise UnsupportedRequestError(
            "model", "use_own_key: true requires model to be \"claude\" or \"openai\".",
        )
    if body.get("stream"):
        raise UnsupportedRequestError("stream", "Streaming responses are not yet supported.")

    query: dict = {"query": question, "study": body.get("domain") or "default"}
    if model in _BYOK_MODELS:
        query["model"] = model
    max_citations = body.get("max_citations")
    if isinstance(max_citations, (int, float)) and not isinstance(max_citations, bool) and max_citations > 0:
        query["top_k"] = int(max_citations)
    return query


def build_rag_search_query(body: dict) -> dict:
    """Translate a public /v1/literature/search request body into RAG's
    POST /v1/query body (with mode="search" set by the caller, not here --
    that's the one field this function doesn't own, since it's not part of
    the public contract). Raises UnsupportedRequestError for a missing/
    blank question, the only field this endpoint requires.

    Unlike build_rag_query above, model/use_own_key/stream are not
    validated here at all: search is retrieval-only regardless of what a
    caller sends for them, so there is no "unsupported" case for fields
    that were never going to change this call's behavior.
    """
    if not isinstance(body, dict):
        raise UnsupportedRequestError("body", "Request body must be a JSON object.")

    question = body.get("question")
    if not isinstance(question, str) or not question.strip():
        raise UnsupportedRequestError("question", "\"question\" is required and must be a non-empty string.")

    query: dict = {"query": question, "study": body.get("domain") or "default", "mode": "search"}
    max_results = body.get("max_results")
    if isinstance(max_results, (int, float)) and not isinstance(max_results, bool) and max_results > 0:
        query["top_k"] = int(max_results)
    return query


def build_public_search(rag_result: dict, *, domain, request_id: str, latency_ms: int) -> dict:
    """Translate RAG's /v1/query (mode="search") response into the frozen
    public /v1/literature/search response shape: ranked documents, no
    generated answer."""
    documents = rag_result.get("documents") or []
    results = [
        {
            "pmid": doc.get("pmid"),
            "title": doc.get("title"),
            "year": doc.get("year"),
            "score": doc.get("citation_confidence", doc.get("similarity_score")),
            # The design doc calls this a "snippet"; RAG only has the full
            # abstract text to offer, not a separately-generated excerpt,
            # so that's what's returned under this name rather than
            # fabricating a truncation.
            "snippet": doc.get("abstract"),
        }
        for doc in documents
    ]
    return {
        "id": f"srch_{request_id or uuid.uuid4().hex}",
        "results": results,
        "domain": rag_result.get("study", domain),
        "usage": {
            "searches": 1,
            "latency_ms": latency_ms,
        },
    }


def build_public_answer(rag_result: dict, *, domain, request_id: str, latency_ms: int) -> dict:
    """Translate RAG's /v1/query response into the frozen public
    /v1/literature/answers response shape."""
    summary = rag_result.get("summary") or {}
    documents = rag_result.get("documents") or []
    citations = [
        {
            "pmid": doc.get("pmid"),
            "title": doc.get("title"),
            "year": doc.get("year"),
            "score": doc.get("citation_confidence", doc.get("similarity_score")),
        }
        for doc in documents
    ]
    return {
        "id": f"ans_{request_id or uuid.uuid4().hex}",
        "answer": summary.get("text", ""),
        "citations": citations,
        "model": summary.get("model"),
        # M16: "omnibioai_gpu" when RAG used its own default model,
        # "claude"/"openai" when this call was BYOK-routed -- RAG's own
        # summary.model_source already reflects which one actually
        # happened (see that repo's resolve_chat_model), so this just
        # relays it rather than hardcoding the pre-M16 default.
        "model_source": summary.get("model_source", "omnibioai_gpu"),
        "domain": rag_result.get("study", domain),
        "usage": {
            "queries": 1,
            # M16: real counts for a BYOK-routed call (RAG's own
            # provider client reports them); still None for the default
            # path, since Ollama's own response carries no token count
            # at all -- reporting a fabricated one would be worse than
            # omitting it.
            "input_tokens": summary.get("input_tokens"),
            "output_tokens": summary.get("output_tokens"),
            "billed_by": "query",
            "latency_ms": latency_ms,
        },
    }


# ---------------------------------------------------------------------------
# M13 (design audit gap #9): omni_sk_test_ keys get a canned, deterministic
# response in the exact shape build_public_answer/build_public_search
# produce -- never a real RAG call, never a real citation, never counted
# against quota or billed. Empty citations/results rather than fabricated
# literature data: a test key's whole point is exercising a caller's own
# integration code (idempotency handling, response parsing, error paths),
# not pretending to answer a real biomedical question.
# ---------------------------------------------------------------------------


def build_test_answer(*, domain, request_id: str, latency_ms: int) -> dict:
    return {
        "id": f"ans_test_{request_id or uuid.uuid4().hex}",
        "answer": "This is a canned test-mode response. No literature service was called, "
                  "and this request was not billed.",
        "citations": [],
        "model": "test",
        "model_source": "test",
        "domain": domain or "default",
        "usage": {
            "queries": 0,
            "input_tokens": None,
            "output_tokens": None,
            "billed_by": "query",
            "latency_ms": latency_ms,
        },
    }


def build_test_search(*, domain, request_id: str, latency_ms: int) -> dict:
    return {
        "id": f"srch_test_{request_id or uuid.uuid4().hex}",
        "results": [],
        "domain": domain or "default",
        "usage": {
            "searches": 0,
            "latency_ms": latency_ms,
        },
    }
