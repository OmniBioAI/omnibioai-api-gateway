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
# default via this sentinel-free "default" shorthand. Any other value
# is a model this gateway has no route for yet.
_NO_MODEL_OVERRIDE = (None, "", "default")


def build_rag_query(body: dict) -> dict:
    """Translate a public /v1/literature/answers request body into RAG's
    POST /v1/query body. Raises UnsupportedRequestError for a field this
    gateway cannot yet honor."""
    if not isinstance(body, dict):
        raise UnsupportedRequestError("body", "Request body must be a JSON object.")

    question = body.get("question")
    if not isinstance(question, str) or not question.strip():
        raise UnsupportedRequestError("question", "\"question\" is required and must be a non-empty string.")

    if body.get("model") not in _NO_MODEL_OVERRIDE:
        raise UnsupportedRequestError(
            "model", f"Model {body.get('model')!r} is not yet supported; omit this field to use the default model.",
        )
    if body.get("use_own_key"):
        raise UnsupportedRequestError("use_own_key", "Bring-your-own-key is not yet supported.")
    if body.get("stream"):
        raise UnsupportedRequestError("stream", "Streaming responses are not yet supported.")

    query: dict = {"query": question, "study": body.get("domain") or "default"}
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
        # Only one model source exists today -- RAG's own GPU-hosted
        # model. Claude/OpenAI routing and BYOK (design "largest gaps"
        # #4) would each need their own model_source value; until they
        # exist, build_rag_query above already rejects any request that
        # would need one.
        "model_source": "omnibioai_gpu",
        "domain": rag_result.get("study", domain),
        "usage": {
            "queries": 1,
            # No per-provider token accounting exists yet (same gap #4)
            # -- reporting a fabricated count here would be worse than
            # omitting it.
            "input_tokens": None,
            "output_tokens": None,
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
