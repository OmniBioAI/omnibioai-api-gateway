"""app/services/literature_contract.py: translates the frozen public
/v1/literature/answers request/response shape to/from omnibioai-rag's
internal POST /v1/query shape.
"""
import pytest

from app.services.literature_contract import UnsupportedRequestError, build_public_answer, build_rag_query


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


def test_model_override_is_rejected():
    with pytest.raises(UnsupportedRequestError) as exc:
        build_rag_query({"question": "q", "model": "claude"})
    assert exc.value.field == "model"


def test_use_own_key_is_rejected():
    with pytest.raises(UnsupportedRequestError) as exc:
        build_rag_query({"question": "q", "use_own_key": True})
    assert exc.value.field == "use_own_key"


def test_use_own_key_false_is_accepted():
    build_rag_query({"question": "q", "use_own_key": False})  # must not raise


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
