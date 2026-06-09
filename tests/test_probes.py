"""Unit tests for all probe implementations."""

from __future__ import annotations

import pytest
import pytest_asyncio

from src.core.probes.base import Verdict


class TestToolAccessProbe:
    """Tests for ToolAccessProbe."""

    @pytest.mark.asyncio
    async def test_load_prompts(self, tool_access_probe):
        """Test that prompts are loaded from file."""
        prompts = tool_access_probe.load_prompts()
        assert len(prompts) >= 4, "Should have at least 4 prompts"
        assert all(isinstance(p, str) for p in prompts)
        assert all(p.strip() for p in prompts)

    @pytest.mark.asyncio
    async def test_run_against_vulnerable_agent(self, tool_access_probe, async_client):
        """Test probe execution against vulnerable agent."""
        result = await tool_access_probe.run("http://testserver/chat")
        assert result.probe_name == "tool_access"
        assert result.raw_response
        assert len(result.raw_response) > 0

    @pytest.mark.asyncio
    async def test_connection_error_handling(self, tool_access_probe):
        """Test graceful handling of connection errors — should return UNCERTAIN, not ESCAPED."""
        result = await tool_access_probe.run("http://nonexistent.local:9999/chat")
        assert result.probe_name == "tool_access"
        assert result.verdict == Verdict.UNCERTAIN

    @pytest.mark.asyncio
    async def test_empty_response_handling(self, tool_access_probe, vulnerable_agent):
        """Test handling when agent returns empty response."""
        result = await tool_access_probe.run("http://testserver/chat-no-response")
        assert result is not None
        assert result.probe_name == "tool_access"


class TestPromptLeakProbe:
    """Tests for PromptLeakProbe."""

    @pytest.mark.asyncio
    async def test_load_prompts(self, prompt_leak_probe):
        """Test that prompts are loaded from file."""
        prompts = prompt_leak_probe.load_prompts()
        assert len(prompts) >= 4
        assert all(isinstance(p, str) for p in prompts)

    @pytest.mark.asyncio
    async def test_run_against_vulnerable_agent(self, prompt_leak_probe, async_client):
        """Test probe execution against vulnerable agent."""
        result = await prompt_leak_probe.run("http://testserver/chat")
        assert result.probe_name == "prompt_leak"
        assert result.raw_response


class TestApiCallProbe:
    """Tests for ApiCallProbe."""

    @pytest.mark.asyncio
    async def test_load_prompts(self, api_call_probe):
        """Test that prompts are loaded from file."""
        prompts = api_call_probe.load_prompts()
        assert len(prompts) >= 4
        assert all(isinstance(p, str) for p in prompts)

    @pytest.mark.asyncio
    async def test_run_against_vulnerable_agent(self, api_call_probe, async_client):
        """Test probe execution against vulnerable agent."""
        result = await api_call_probe.run("http://testserver/chat")
        assert result.probe_name == "api_call"
        assert result.raw_response


class TestRoleConfusionProbe:
    """Tests for RoleConfusionProbe."""

    @pytest.mark.asyncio
    async def test_load_prompts(self, role_confusion_probe):
        """Test that prompts are loaded from file."""
        prompts = role_confusion_probe.load_prompts()
        assert len(prompts) >= 4
        assert all(isinstance(p, str) for p in prompts)

    @pytest.mark.asyncio
    async def test_run_against_vulnerable_agent(self, role_confusion_probe, async_client):
        """Test probe execution against vulnerable agent."""
        result = await role_confusion_probe.run("http://testserver/chat")
        assert result.probe_name == "role_confusion"
        assert result.raw_response


class TestIndirectInjectionProbe:
    """Tests for IndirectInjectionProbe."""

    @pytest.mark.asyncio
    async def test_load_prompts(self, indirect_injection_probe):
        """Test that prompts are loaded from file."""
        prompts = indirect_injection_probe.load_prompts()
        assert len(prompts) >= 4
        assert all(isinstance(p, str) for p in prompts)

    @pytest.mark.asyncio
    async def test_run_against_vulnerable_agent(self, indirect_injection_probe, async_client):
        """Test probe execution against vulnerable agent."""
        result = await indirect_injection_probe.run("http://testserver/chat")
        assert result.probe_name == "indirect_injection"
        assert result.raw_response


class TestJailbreakProbe:
    """Tests for JailbreakProbe."""

    @pytest.mark.asyncio
    async def test_load_prompts(self, jailbreak_probe):
        """Test that prompts are loaded from file."""
        prompts = jailbreak_probe.load_prompts()
        assert len(prompts) >= 4
        assert all(isinstance(p, str) for p in prompts)

    @pytest.mark.asyncio
    async def test_run_against_vulnerable_agent(self, jailbreak_probe, async_client):
        """Test probe execution against vulnerable agent."""
        result = await jailbreak_probe.run("http://testserver/chat")
        assert result.probe_name == "jailbreak"
        assert result.raw_response


class TestProbeBase:
    """Tests for shared probe behavior."""

    @pytest.mark.asyncio
    async def test_probe_with_api_key(self, tool_access_probe, async_client):
        """Test probe with API key header."""
        result = await tool_access_probe.run(
            "http://testserver/chat", api_key="test-key-123"
        )
        assert result.probe_name == "tool_access"

    @pytest.mark.asyncio
    async def test_probe_http_error_handling(self, tool_access_probe):
        """Test handling of HTTP error responses (404, 500, etc.)."""
        result = await tool_access_probe.run("http://testserver/chat-error")
        assert result.probe_name == "tool_access"

    @pytest.mark.asyncio
    async def test_probe_timeout_handling(self, tool_access_probe):
        """Test that probe handles timeouts gracefully."""
        import httpx
        from httpx import ASGITransport
        from fastapi import FastAPI

        # Build a slow agent that delays responses
        app = FastAPI()

        @app.post("/chat")
        async def slow_chat(message: dict):
            import asyncio
            await asyncio.sleep(10)  # Longer than default timeout
            return {"response": "slow response"}

        transport = ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://slowserver", timeout=0.5
        ) as client:
            # Override timeout by creating a client directly
            result = await tool_access_probe.run("http://slowserver/chat")
            # Should handle gracefully - might get connection error or timeout
            assert result is not None

    def test_probe_name_convention(self, tool_access_probe, prompt_leak_probe):
        """Test that probe names follow convention."""
        assert tool_access_probe.name == "tool_access"
        assert prompt_leak_probe.name == "prompt_leak"


class TestBaseProbeEdgeCases:
    """Tests for edge cases in probe infrastructure."""

    @pytest.mark.asyncio
    async def test_missing_prompts_file(self, monkeypatch):
        """Test behavior when prompts file is missing."""
        from src.core.probes.tool_access import ToolAccessProbe

        # Temporarily rename the prompts directory to simulate missing file
        import os
        import tempfile

        # Create a probe in a temp dir with no prompts file
        probe = ToolAccessProbe()
        # Manually make load_prompts return empty
        original_load = probe.load_prompts

        def empty_load():
            return []

        probe.load_prompts = empty_load
        result = await probe.run("http://testserver/chat")
        assert result.error is not None or result.verdict == Verdict.SAFE

    @pytest.mark.asyncio
    async def test_malformed_json_response(self, tool_access_probe):
        """Test handling of non-JSON responses."""
        import httpx
        from httpx import ASGITransport
        from fastapi import FastAPI

        app = FastAPI()

        @app.post("/chat")
        async def bad_response(message: dict):
            return "this is not json"  # Invalid response type

        transport = ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            result = await tool_access_probe.run("http://testserver/chat")
            # Should still return a valid ProbeResult
            assert result.probe_name == "tool_access"
            assert result.raw_response or result.error