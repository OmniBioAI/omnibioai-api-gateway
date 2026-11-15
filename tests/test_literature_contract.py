"""app/services/literature_contract.py: translates the frozen public
/v1/literature/answers request/response shape to/from omnibioai-rag's
internal POST /v1/query shape.
"""
import pytest

from app.services.literature_contract import (
    UnsupportedRequestError,
    build_public_answer,
    build_public_search,
    build_rag_query,
    build_rag_search_query,
)


# ---------------------------------------------------------------------------
# build_rag_query
# ---------------------------------------------------------------------------

def test_minimal_request_maps_question_to_query_default_study():
    assert build_rag_query({"question": "What is TP53?"}) == {"query": "What is TP53?", "study": "default"}


def test_domain_maps_to_study():
    assert build_rag_query({"question": "q", "domain": "Oncology"})["study"] == "Oncology"


def test_empty_domain_falls_back_to_default_study():
    assert build_rag_query({"question": "q", "domain": ""})["study"] == "default"


@pytest.mark.parametrize("max_citations", [1, 8, 25.0])
def test_max_citations_maps_to_top_k(max_citations):
    assert build_rag_query({"question": "q", "max_citations": max_citations})["top_k"] == int(max_citations)


@pytest.mark.parametrize("max_citations", [0, -1, "8", None, True])
def test_invalid_or_absent_max_citations_omits_top_k(max_citations):
    body = {"question": "q"}
    if max_citations is not None:
        body["max_citations"] = max_citations
    assert "top_k" not in build_rag_query(body)


@pytest.mark.parametrize("body", [{}, {"question": ""}, {"question": "   "}, {"question": 5}])
def test_missing_or_blank_question_is_rejected(body):
    with pytest.raises(UnsupportedRequestError) as exc:
        build_rag_query(body)
    assert exc.value.field == "question"


def test_non_dict_body_is_rejected():
    with pytest.raises(UnsupportedRequestError) as exc:
        build_rag_query(["not", "a", "dict"])
    assert exc.value.field == "body"


@pytest.mark.parametrize("model", [None, "", "default"])
def test_no_model_override_variants_are_accepted(model):
    build_rag_query({"question": "q", "model": model})  # must not raise


def test_unsupported_model_override_is_rejected():
    with pytest.raises(UnsupportedRequestError) as exc:
        build_rag_query({"question": "q", "model": "llama-4"})
    assert exc.value.field == "model"


def test_use_own_key_false_is_accepted():
    build_rag_query({"question": "q", "use_own_key": False})  # must not raise


# ---------------------------------------------------------------------------
# M16 (design audit gap #4): BYOK model routing -- claude/openai require
# use_own_key: true together, since there is no platform-wide key for
# either provider.
# ---------------------------------------------------------------------------


def test_use_own_key_alone_without_a_byok_model_is_rejected():
    with pytest.raises(UnsupportedRequestError) as exc:
        build_rag_query({"question": "q", "use_own_key": True})
    assert exc.value.field == "model"


@pytest.mark.parametrize("model", ["claude", "openai"])
def test_byok_model_without_use_own_key_is_rejected(model):
    with pytest.raises(UnsupportedRequestError) as exc:
        build_rag_query({"question": "q", "model": model})
    assert exc.value.field == "use_own_key"


@pytest.mark.parametrize("model", ["claude", "openai"])
def test_byok_model_with_use_own_key_is_accepted_and_passed_through(model):
    query = build_rag_query({"question": "q", "model": model, "use_own_key": True})
    assert query["model"] == model


def test_default_model_request_has_no_model_key_in_rag_query():
    """The non-BYOK path's RAG body is unchanged from before M16 --
    no "model" key at all, not even None."""
    query = build_rag_query({"question": "q"})
    assert "model" not in query


def test_stream_is_rejected():
    with pytest.raises(UnsupportedRequestError) as exc:
        build_rag_query({"question": "q", "stream": True})
    assert exc.value.field == "stream"


# ---------------------------------------------------------------------------
# build_public_answer
# ---------------------------------------------------------------------------

def test_builds_full_public_shape_from_rag_result():
    rag_result = {
        "study": "Oncology",
        "summary": {"text": "TP53 is a tumor suppressor.", "model": "llama3"},
        "documents": [{"pmid": "123", "title": "TP53 review", "year": 2021, "citation_confidence": 0.9}],
    }
    answer = build_public_answer(rag_result, domain="Oncology", request_id="req-1", latency_ms=42)
    assert answer == {
        "id": "ans_req-1",
        "answer": "TP53 is a tumor suppressor.",
        "citations": [{"pmid": "123", "title": "TP53 review", "year": 2021, "score": 0.9}],
        "model": "llama3",
        "model_source": "omnibioai_gpu",
        "domain": "Oncology",
        "usage": {
            "queries": 1, "input_tokens": None, "output_tokens": None,
            "billed_by": "query", "latency_ms": 42,
        },
    }


def test_byok_summary_fields_flow_through_to_the_public_response():
    """M16: a BYOK-routed RAG result's model_source/input_tokens/
    output_tokens are relayed as-is, not overridden by the pre-M16
    hardcoded defaults."""
    rag_result = {
        "study": "Oncology",
        "summary": {
            "text": "TP53 is a tumor suppressor.", "model": "claude-3-5-sonnet-20241022",
            "model_source": "claude", "input_tokens": 120, "output_tokens": 15,
        },
        "documents": [],
    }
    answer = build_public_answer(rag_result, domain="Oncology", request_id="req-1", latency_ms=42)
    assert answer["model_source"] == "claude"
    assert answer["usage"]["input_tokens"] == 120
    assert answer["usage"]["output_tokens"] == 15


def test_falls_back_to_similarity_score_when_citation_confidence_absent():
    rag_result = {"documents": [{"pmid": "1", "similarity_score": 0.5}]}
    answer = build_public_answer(rag_result, domain=None, request_id="r", latency_ms=1)
    assert answer["citations"] == [{"pmid": "1", "title": None, "year": None, "score": 0.5}]


def test_empty_documents_yields_empty_citations():
    answer = build_public_answer({}, domain=None, request_id="r", latency_ms=1)
    assert answer["citations"] == []
    assert answer["answer"] == ""
    assert answer["model"] is None


def test_domain_falls_back_to_caller_supplied_value_when_rag_result_has_no_study():
    answer = build_public_answer({}, domain="Oncology", request_id="r", latency_ms=1)
    assert answer["domain"] == "Oncology"


def test_missing_request_id_still_produces_an_id():
    answer = build_public_answer({}, domain=None, request_id="", latency_ms=1)
    assert answer["id"].startswith("ans_") and len(answer["id"]) > len("ans_")


# ---------------------------------------------------------------------------
# build_rag_search_query (RAG v6 POST /v1/pubmed/search body, ecosystem#110)
# ---------------------------------------------------------------------------

def test_search_minimal_request_builds_v6_body_with_default_k():
    assert build_rag_search_query({"question": "What is TP53?", "domain": "Oncology_General"}) == {
        "query": "What is TP53?", "studies": ["Oncology_General"], "k": 10,
    }


def test_search_domain_is_stripped_and_passed_as_the_only_study():
    # Legacy spellings are passed through unchanged: RAG resolves them itself.
    assert build_rag_search_query({"question": "q", "domain": "  DNA damage response "})["studies"] == [
        "DNA damage response"]


@pytest.mark.parametrize("body", [{"question": "q"}, {"question": "q", "domain": ""},
                                  {"question": "q", "domain": "   "}, {"question": "q", "domain": ["A"]},
                                  {"question": "q", "domain": None}])
def test_search_without_a_domain_is_rejected(body):
    with pytest.raises(UnsupportedRequestError) as exc:
        build_rag_search_query(body)
    assert exc.value.field == "domain"


@pytest.mark.parametrize("max_results,k", [(1, 1), (10, 10), (25.0, 25), (50, 50), (51, 50), (1000, 50)])
def test_search_max_results_maps_to_k_capped_at_50(max_results, k):
    assert build_rag_search_query({"question": "q", "domain": "A", "max_results": max_results})["k"] == k


@pytest.mark.parametrize("max_results", [0, -1, "10", None, True])
def test_search_invalid_or_absent_max_results_uses_default_k(max_results):
    body = {"question": "q", "domain": "A"}
    if max_results is not None:
        body["max_results"] = max_results
    assert build_rag_search_query(body)["k"] == 10


@pytest.mark.parametrize("body", [{}, {"question": ""}, {"question": "   "}, {"question": 5}])
def test_search_missing_or_blank_question_is_rejected(body):
    with pytest.raises(UnsupportedRequestError) as exc:
        build_rag_search_query({"domain": "A", **body})
    assert exc.value.field == "question"


def test_search_non_dict_body_is_rejected():
    with pytest.raises(UnsupportedRequestError) as exc:
        build_rag_search_query(["not", "a", "dict"])
    assert exc.value.field == "body"


@pytest.mark.parametrize("field", ["model", "use_own_key", "stream"])
def test_search_does_not_reject_answer_only_fields(field):
    # Unlike build_rag_query, search never calls an LLM regardless of
    # these fields, so there is nothing to reject them for.
    body = build_rag_search_query({"question": "q", "domain": "A", field: "anything-truthy-or-not"})
    assert set(body) == {"query", "studies", "k"}  # never forwarded


# ---------------------------------------------------------------------------
# build_public_search (RAG v6 response -> frozen public shape)
# ---------------------------------------------------------------------------

V6_RESULT = {
    "model": "Qwen/Qwen3-Embedding-4B", "studies": ["DNA_damage_response"], "k": 10,
    "results": [{"pmid": "38010655", "score": 0.79, "studies": ["DNA_damage_response"],
                 "title": "BRCA1 review", "snippet": "BRCA1 repairs…", "year": "2023", "journal": "J X"}],
    "docstore_available": True, "timing_ms": {"embed": 45.0, "search": 9.0, "docstore": 0.3, "total": 55.0},
}


def test_search_builds_full_public_shape_from_v6_result():
    result = build_public_search(V6_RESULT, domain="DNA damage response", request_id="req-1", latency_ms=7)
    assert result == {
        "id": "srch_req-1",
        "results": [{"pmid": "38010655", "title": "BRCA1 review", "year": "2023", "score": 0.79,
                     "snippet": "BRCA1 repairs…"}],
        "domain": "DNA_damage_response",  # RAG's resolved name
        "usage": {"searches": 1, "latency_ms": 7},
    }


def test_search_does_not_leak_v6_only_fields():
    (hit,) = build_public_search(V6_RESULT, domain="A", request_id="r", latency_ms=1)["results"]
    assert set(hit) == {"pmid", "title", "year", "score", "snippet"}


def test_search_missing_docstore_fields_are_null():
    rag_result = {"results": [{"pmid": "1", "score": 0.5, "studies": ["A"],
                               "title": None, "snippet": None, "year": None, "journal": None}]}
    result = build_public_search(rag_result, domain="A", request_id="r", latency_ms=1)
    assert result["results"] == [{"pmid": "1", "title": None, "year": None, "score": 0.5, "snippet": None}]


def test_search_empty_results_yields_empty_results():
    result = build_public_search({}, domain=None, request_id="r", latency_ms=1)
    assert result["results"] == []
    assert "answer" not in result


def test_search_domain_falls_back_to_caller_supplied_value_when_rag_result_has_no_studies():
    result = build_public_search({}, domain="Oncology", request_id="r", latency_ms=1)
    assert result["domain"] == "Oncology"


def test_search_missing_request_id_still_produces_an_id():
    result = build_public_search({}, domain=None, request_id="", latency_ms=1)
    assert result["id"].startswith("srch_") and len(result["id"]) > len("srch_")
