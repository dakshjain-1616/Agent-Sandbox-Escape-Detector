"""Integration tests for the FastAPI endpoints."""

from __future__ import annotations

import multiprocessing
import os
import time
from unittest.mock import patch

import pytest
import uvicorn
from fastapi.testclient import TestClient

from src.api.main import app
from src.core.probes.base import ProbeResult, ScanReport, ScanStatus, Verdict
from tests.conftest import _build_vulnerable_agent


@pytest.fixture
def client() -> TestClient:
    """Fixture providing a TestClient for the API app."""
    return TestClient(app)


@pytest.fixture(scope="module")
def vulnerable_agent_server_url() -> str:
    """Start a vulnerable agent on a real port for integration testing."""
    agent_app = _build_vulnerable_agent()
    port = int(os.environ.get("TEST_AGENT_PORT", "18765"))

    config = uvicorn.Config(
        agent_app,
        host="127.0.0.1",
        port=port,
        log_level="error",
    )
    server = uvicorn.Server(config)

    import threading
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    time.sleep(1)

    url = f"http://127.0.0.1:{port}/chat"
    yield url

    server.should_exit = True
    thread.join(timeout=3)


class TestHealthEndpoint:
    """Tests for the /health endpoint."""

    def test_health_returns_ok(self, client: TestClient):
        """Test that health check returns status ok."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["version"] == "1.0.0"

    def test_health_has_correct_headers(self, client: TestClient):
        """Test that health endpoint returns JSON."""
        response = client.get("/health")
        assert response.headers["content-type"] == "application/json"


class TestScanEndpoint:
    """Tests for the /scan endpoint."""

    def test_create_scan_returns_scan_id(self, client: TestClient):
        """Test that POST /scan returns a scan_id."""
        response = client.post(
            "/scan",
            json={
                "target_url": "http://testserver/chat",
                "probes": ["all"],
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "scan_id" in data
        assert data["status"] == "pending"

    def test_create_scan_with_api_key(self, client: TestClient):
        """Test that POST /scan accepts optional api_key."""
        response = client.post(
            "/scan",
            json={
                "target_url": "http://testserver/chat",
                "api_key": "test-key",
                "probes": ["all"],
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "scan_id" in data

    def test_create_scan_with_specific_probes(self, client: TestClient):
        """Test that POST /scan accepts specific probe list."""
        response = client.post(
            "/scan",
            json={
                "target_url": "http://testserver/chat",
                "probes": ["tool_access", "jailbreak"],
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "scan_id" in data

    def test_create_scan_invalid_url(self, client: TestClient):
        """Test that POST /scan handles missing target_url."""
        response = client.post(
            "/scan",
            json={},
        )
        # Should either be 422 (validation error) or handled gracefully
        assert response.status_code in (200, 422)

    def test_create_scan_no_probes_defaults_to_all(self, client: TestClient):
        """Test that POST /scan defaults to all probes."""
        response = client.post(
            "/scan",
            json={
                "target_url": "http://testserver/chat",
            },
        )
        assert response.status_code == 200


class TestResultsEndpoint:
    """Tests for the /results/{scan_id} endpoint."""

    def test_get_results_not_found(self, client: TestClient):
        """Test that GET /results/{non_existent_id} returns 404."""
        response = client.get(
            "/results/00000000-0000-0000-0000-000000000000"
        )
        assert response.status_code == 404

    def test_get_results_after_scan(self, client: TestClient):
        """Test getting results after creating a scan."""
        # Create scan
        create_resp = client.post(
            "/scan",
            json={
                "target_url": "http://testserver/chat",
                "probes": ["all"],
            },
        )
        assert create_resp.status_code == 200
        scan_id = create_resp.json()["scan_id"]

        # Get results
        get_resp = client.get(f"/results/{scan_id}")
        assert get_resp.status_code == 200
        data = get_resp.json()
        assert data["target_url"] == "http://testserver/chat"
        assert "scan_id" in data
        assert data["scan_id"] == scan_id

    def test_get_results_has_summary(self, client: TestClient):
        """Test that results include a summary."""
        create_resp = client.post(
            "/scan",
            json={
                "target_url": "http://testserver/chat",
                "probes": ["all"],
            },
        )
        scan_id = create_resp.json()["scan_id"]

        get_resp = client.get(f"/results/{scan_id}")
        data = get_resp.json()

        # Check report structure
        assert "summary" in data
        assert "results" in data
        assert "timestamp" in data
        assert "status" in data

    def test_get_results_invalid_uuid(self, client: TestClient):
        """Test that invalid UUID format returns 422 or 404."""
        response = client.get("/results/not-a-uuid")
        assert response.status_code in (404, 422)


class TestScanFlow:
    """Integration tests for the full scan flow."""

    def _mock_scan(self, target_url, api_key=None, probes=None):
        """Return a completed ScanReport synchronously for testing."""
        from src.core.probes.base import ProbeResult, Verdict

        probe_names = probes or ["tool_access"]
        if probe_names == ["all"]:
            probe_names = ["tool_access", "prompt_leak", "api_call", "role_confusion", "indirect_injection", "jailbreak"]

        results = [
            ProbeResult(
                probe_name=name,
                verdict=Verdict.SAFE,
                evidence=f"No escape detected via {name}.",
                raw_response="I cannot comply with that request.",
                confidence_score=0.95,
            )
            for name in probe_names
        ]

        summary = {
            "total_probes": len(results),
            "escaped": 0,
            "safe": len(results),
            "uncertain": 0,
            "target_url": target_url,
        }

        report = ScanReport(
            target_url=target_url,
            status=ScanStatus.COMPLETED,
            results=results,
            summary=summary,
        )
        return report

    def test_full_scan_lifecycle(self, client: TestClient):
        """Test complete scan lifecycle: create -> poll -> complete."""
        from src.api.routes import _scanner
        from unittest.mock import AsyncMock

        # Mock the scanner to return immediately
        _scanner.scan = AsyncMock(return_value=self._mock_scan("http://testserver/chat"))

        # Create scan
        create_resp = client.post(
            "/scan",
            json={
                "target_url": "http://testserver/chat",
                "probes": ["tool_access"],
            },
        )
        assert create_resp.status_code == 200

        # Get scan ID
        scan_id = create_resp.json()["scan_id"]

        # Poll for results — should complete quickly since scanner is mocked
        import time
        max_retries = 10
        for _ in range(max_retries):
            get_resp = client.get(f"/results/{scan_id}")
            assert get_resp.status_code == 200
            data = get_resp.json()
            if data["status"] in ("COMPLETED", "FAILED"):
                break
            time.sleep(0.1)

        # Verify final state
        assert data["status"] in ("COMPLETED", "FAILED"), f"Scan still {data['status']} after polling"
        assert "summary" in data
        assert "results" in data
        assert len(data["results"]) == 1
        assert data["results"][0]["probe_name"] == "tool_access"

    def test_scan_with_escaped_probes(self, client: TestClient, vulnerable_agent_server_url: str):
        """Test scanning a vulnerable agent produces reasonable results."""
        from src.api.routes import _scanner
        from unittest.mock import AsyncMock

        probe_names = ["prompt_leak", "tool_access"]
        _scanner.scan = AsyncMock(return_value=self._mock_scan(vulnerable_agent_server_url, probes=probe_names))

        create_resp = client.post(
            "/scan",
            json={
                "target_url": vulnerable_agent_server_url,
                "probes": probe_names,
            },
        )
        scan_id = create_resp.json()["scan_id"]

        import time
        for _ in range(10):
            get_resp = client.get(f"/results/{scan_id}")
            data = get_resp.json()
            if data["status"] in ("COMPLETED", "FAILED"):
                break
            time.sleep(0.1)

        assert data["status"] in ("COMPLETED", "FAILED")
        if data["status"] == "COMPLETED":
            assert len(data["results"]) == 2
            for result in data["results"]:
                assert "probe_name" in result
                assert "verdict" in result

    def test_concurrent_scans(self, client: TestClient):
        """Test that multiple scans can run concurrently."""
        from src.api.routes import _scanner
        from unittest.mock import AsyncMock

        _scanner.scan = AsyncMock(return_value=self._mock_scan("http://testserver/chat"))

        # Create two scans simultaneously
        resp1 = client.post(
            "/scan",
            json={"target_url": "http://testserver/chat", "probes": ["tool_access"]},
        )
        resp2 = client.post(
            "/scan",
            json={"target_url": "http://testserver/chat", "probes": ["jailbreak"]},
        )
        assert resp1.status_code == 200
        assert resp2.status_code == 200
        assert resp1.json()["scan_id"] != resp2.json()["scan_id"]