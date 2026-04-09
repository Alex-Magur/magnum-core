import pytest
from unittest.mock import AsyncMock, patch
from sandbox.network.proxy import EgressProxy, EgressBlocked
from sandbox.network.ssrf_guard import SSRFViolation
from sandbox.config import SandboxPolicy, SandboxSettings


@pytest.fixture
def policy():
    return SandboxPolicy.from_settings(SandboxSettings())


@pytest.fixture
def proxy(policy):
    return EgressProxy(policy)


@pytest.mark.asyncio
async def test_proxy_ssrf_failure(proxy):
    """Verify that SSRF violations lead to EgressBlocked."""
    with patch.object(proxy.ssrf_guard, "check_url_async", side_effect=SSRFViolation("SSRF Detected")):
        with pytest.raises(EgressBlocked, match="SSRF violation"):
            await proxy.check_egress("GET", "http://127.0.0.1/metadata")


@pytest.mark.asyncio
async def test_proxy_opa_denial(proxy):
    """Verify that OPA policy denials lead to EgressBlocked."""
    # Mock SSRF success
    with patch.object(proxy.ssrf_guard, "check_url_async", new_callable=AsyncMock):
        # Mock OPA denial
        mock_decision = AsyncMock()
        mock_decision.allowed = False
        mock_decision.reason = "Host not in allowlist"
        mock_decision.policy_decision_id = "test-123"
        
        with patch.object(proxy.opa_evaluator, "evaluate", return_value=mock_decision):
            with pytest.raises(EgressBlocked, match="OPA policy violation: Host not in allowlist"):
                await proxy.check_egress("GET", "https://malicious.com")


@pytest.mark.asyncio
async def test_proxy_success(proxy):
    """Verify that successful checks result in no exception."""
    with patch.object(proxy.ssrf_guard, "check_url_async", new_callable=AsyncMock), \
         patch.object(proxy.opa_evaluator, "evaluate") as mock_eval:
        
        mock_decision = AsyncMock()
        mock_decision.allowed = True
        mock_decision.policy_decision_id = "test-ok"
        mock_eval.return_value = mock_decision
        
        # Should not raise
        await proxy.check_egress("POST", "https://api.github.com/repos/test")
        
        mock_eval.assert_called_once()
        input_doc = mock_eval.call_args[0][0]
        assert input_doc["method"] == "POST"
        assert input_doc["host"] == "api.github.com"
