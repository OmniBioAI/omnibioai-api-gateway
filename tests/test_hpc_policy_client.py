"""Tests for app/services/hpc_policy_client.py — HPCPolicyClient unit tests."""
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.services.hpc_policy_client import HPCPolicyClient, HPC_COMPUTE_SERVICES


@pytest.fixture
def hpc_client():
    mock_http = AsyncMock()
    with patch("app.services.hpc_policy_client.httpx.AsyncClient", return_value=mock_http):
        client = HPCPolicyClient("http://hpc-service")
    return client, mock_http


def test_is_compute_service_known():
    client = HPCPolicyClient.__new__(HPCPolicyClient)
    client.base_url = ""
    for svc in HPC_COMPUTE_SERVICES:
        assert client.is_compute_service(svc) is True


def test_is_compute_service_unknown():
    client = HPCPolicyClient.__new__(HPCPolicyClient)
    assert client.is_compute_service("unknown-svc") is False


async def test_evaluate_success_cpu(hpc_client):
    client, mock_http = hpc_client
    resp = MagicMock()
    resp.json.return_value = {"allow": True}
    mock_http.post.return_value = resp
    result = await client.evaluate("u1", "tes", trace_id="t1", cpu_hours=2.0)
    assert result == {"allow": True}


async def test_evaluate_gpu_sets_gpu_partition(hpc_client):
    client, mock_http = hpc_client
    resp = MagicMock()
    resp.json.return_value = {"allow": True}
    mock_http.post.return_value = resp
    await client.evaluate("u1", "tes", gpus=2)
    payload = mock_http.post.call_args[1]["json"]
    assert payload["partition"] == "gpu"
    assert payload["gpus"] == 2


async def test_evaluate_no_gpu_sets_cpu_partition(hpc_client):
    client, mock_http = hpc_client
    resp = MagicMock()
    resp.json.return_value = {"allow": True}
    mock_http.post.return_value = resp
    await client.evaluate("u1", "workbench", gpus=0)
    payload = mock_http.post.call_args[1]["json"]
    assert payload["partition"] == "cpu"


async def test_evaluate_sends_correct_headers(hpc_client):
    client, mock_http = hpc_client
    resp = MagicMock()
    resp.json.return_value = {"allow": True}
    mock_http.post.return_value = resp
    await client.evaluate("user42", "tes", trace_id="trace-abc")
    headers = mock_http.post.call_args[1]["headers"]
    assert headers["X-Internal-Service"] == "gateway"
    assert headers["X-Trace-Id"] == "trace-abc"
    assert headers["X-User-Id"] == "user42"


async def test_evaluate_timeout_first_attempt_retries(hpc_client):
    client, mock_http = hpc_client
    resp = MagicMock()
    resp.json.return_value = {"allow": True}
    mock_http.post.side_effect = [httpx.TimeoutException("t/o"), resp]
    result = await client.evaluate("u1", "tes")
    assert result == {"allow": True}
    assert mock_http.post.call_count == 2


async def test_evaluate_timeout_both_attempts_returns_hpc_timeout(hpc_client):
    client, mock_http = hpc_client
    mock_http.post.side_effect = httpx.TimeoutException("t/o")
    result = await client.evaluate("u1", "tes")
    assert result == {"allow": False, "reason": "hpc_timeout"}


async def test_evaluate_generic_exception_returns_hpc_error(hpc_client):
    client, mock_http = hpc_client
    mock_http.post.side_effect = RuntimeError("conn error")
    result = await client.evaluate("u1", "tes")
    assert result == {"allow": False, "reason": "hpc_error"}


async def test_evaluate_all_resource_fields(hpc_client):
    client, mock_http = hpc_client
    resp = MagicMock()
    resp.json.return_value = {"allow": False, "reason": "quota"}
    mock_http.post.return_value = resp
    result = await client.evaluate(
        "u1", "toolserver",
        cpu_hours=10.0, gpu_hours=5.0, gpus=4, memory_gb=32,
    )
    payload = mock_http.post.call_args[1]["json"]
    assert payload["cpu_hours"] == 10.0
    assert payload["gpu_hours"] == 5.0
    assert payload["gpus"] == 4
    assert payload["memory_gb"] == 32
    assert result == {"allow": False, "reason": "quota"}


async def test_evaluate_forwards_roles(hpc_client):
    """PR12: /jobs/evaluate now actually checks roles (gpu_user/
    dgx_access) instead of always approving -- must reach the HPC engine."""
    client, mock_http = hpc_client
    resp = MagicMock()
    resp.json.return_value = {"allow": True}
    mock_http.post.return_value = resp
    await client.evaluate("u1", "tes", roles=["gpu_user", "dgx_access"])
    payload = mock_http.post.call_args[1]["json"]
    assert payload["roles"] == ["gpu_user", "dgx_access"]


async def test_evaluate_defaults_to_no_roles(hpc_client):
    client, mock_http = hpc_client
    resp = MagicMock()
    resp.json.return_value = {"allow": True}
    mock_http.post.return_value = resp
    await client.evaluate("u1", "tes")
    payload = mock_http.post.call_args[1]["json"]
    assert payload["roles"] == []
