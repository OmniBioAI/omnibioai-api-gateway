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
