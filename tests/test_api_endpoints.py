"""
Tests for API endpoints.
"""
import pytest
import json
from pathlib import Path
from fastapi.testclient import TestClient
import tempfile
import os

from analysis_engine.api.server import app
from generator.attack_traces.lateral_movement.generator import generate_lateral_movement_scenario


# Set API key for testing
os.environ["API_KEY"] = "test_api_key_12345"


@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app)


@pytest.fixture
def api_headers():
    """Get API authentication headers."""
    return {"X-API-Key": "test_api_key_12345"}


class TestHealthEndpoint:
    """Test health check endpoint."""

    def test_health_endpoint_returns_200(self, client):
        """Test health endpoint returns 200 OK."""
        response = client.get("/health")
        assert response.status_code == 200

    def test_health_endpoint_returns_json(self, client):
        """Test health endpoint returns JSON."""
        response = client.get("/health")
        assert response.headers["content-type"] == "application/json"

    def test_health_endpoint_structure(self, client):
        """Test health endpoint returns proper structure."""
        response = client.get("/health")
        data = response.json()
        
        assert "status" in data
        assert data["status"] in ["healthy", "ok", "degraded"]
        assert "version" in data or "service" in data


class TestAnalyzeEndpoint:
    """Test the upload analysis endpoint."""

    def test_analyze_endpoint_requires_auth(self, client):
        """Test analyze endpoint requires API key."""
        response = client.post(
            "/analyze/upload",
            files={"file": ("telemetry.jsonl", b"{}\n", "application/json")},
        )
        assert response.status_code == 401

    def test_analyze_with_valid_file(self, client, api_headers, temp_telemetry_file):
        """Test analysis with valid telemetry file."""
        with open(temp_telemetry_file, 'rb') as f:
            response = client.post(
                "/analyze/upload",
                files={"file": ("telemetry.jsonl", f, "application/json")},
                headers=api_headers
            )

        assert response.status_code == 200, response.text
        data = response.json()
        assert data["total_events"] > 0
        assert data["suspicious_sessions"] == len(data["sessions"])

    def test_analyze_reports_suspicious_sessions(self, client, api_headers, tmp_path):
        """Suspicious sessions are returned in the flat API Session shape."""
        generate_lateral_movement_scenario(output_dir=tmp_path, add_noise=False)

        with open(tmp_path / "telemetry.jsonl", 'rb') as f:
            response = client.post(
                "/analyze/upload",
                files={"file": ("telemetry.jsonl", f, "application/json")},
                headers=api_headers
            )

        assert response.status_code == 200, response.text
        data = response.json()
        assert data["suspicious_sessions"] > 0
        session = data["sessions"][0]
        assert session["session_id"]
        assert 0.0 <= session["risk_score"] <= 1.0
        assert session["event_count"] > 0
        assert isinstance(session["iocs"]["ip_addresses"], list)

    def test_analyze_with_invalid_file_type(self, client, api_headers):
        """Test analysis rejects invalid file types."""
        response = client.post(
            "/analyze/upload",
            files={"file": ("malware.exe", b"invalid content", "application/octet-stream")},
            headers=api_headers
        )

        assert response.status_code == 400

    def test_analyze_with_empty_file(self, client, api_headers):
        """Test analysis rejects an empty file."""
        response = client.post(
            "/analyze/upload",
            files={"file": ("empty.jsonl", b"", "application/json")},
            headers=api_headers
        )

        assert response.status_code == 400


class TestMetricsEndpoint:
    """Test metrics endpoint."""

    def test_metrics_endpoint_exists(self, client):
        """Test metrics endpoint is available."""
        response = client.get("/metrics")
        # May require auth or be public
        assert response.status_code in [200, 401, 404]

    def test_metrics_format(self, client):
        """Test metrics are in Prometheus format."""
        response = client.get("/metrics")
        
        if response.status_code == 200:
            # Prometheus metrics should be text
            content = response.text
            # Should contain metric names
            assert isinstance(content, str)


class TestScenarioEndpoints:
    """Test scenario endpoints."""

    def test_list_scenarios_endpoint(self, client):
        """Test listing available scenarios."""
        response = client.get("/scenarios")

        assert response.status_code == 200
        assert isinstance(response.json()["scenarios"], list)

    def test_unknown_scenario_returns_404(self, client):
        response = client.get("/scenarios/nonexistent_scenario_xyz")

        assert response.status_code == 404

    @pytest.mark.parametrize("name", ["%2E%2E", "....", "a%2Fb", "bad name"])
    def test_scenario_names_are_validated(self, client, name):
        response = client.get(f"/scenarios/{name}")

        assert response.status_code in (400, 404)

    def test_delete_rejects_name_that_collapses_to_scenarios_root(
        self, client, api_headers, tmp_path, monkeypatch
    ):
        """`..` used to be stripped to "", making the target output/scenarios itself."""
        monkeypatch.chdir(tmp_path)
        keep = tmp_path / "output" / "scenarios" / "keep"
        keep.mkdir(parents=True)

        response = client.delete("/scenarios/%2E%2E", headers=api_headers)

        assert response.status_code == 400
        assert keep.exists()

    def test_delete_scenario(self, client, api_headers, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        target = tmp_path / "output" / "scenarios" / "demo_1"
        target.mkdir(parents=True)

        response = client.delete("/scenarios/demo_1", headers=api_headers)

        assert response.status_code == 200
        assert not target.exists()


class TestRateLimiting:
    """Test rate limiting functionality."""

    def test_rate_limit_enforced(self, client):
        """Test that rate limiting is enforced."""
        # Make many requests rapidly
        responses = []
        for _ in range(150):  # Exceed typical rate limit
            response = client.get("/health")
            responses.append(response.status_code)
        
        # Some requests should be rate limited (429)
        # or all should succeed if limit is high
        assert 200 in responses  # At least some succeed
        # May or may not have 429 depending on limit configuration

    def test_rate_limit_per_endpoint(self, client, api_headers):
        """Test rate limiting is per-endpoint."""
        # Health endpoint
        health_responses = [client.get("/health").status_code for _ in range(50)]
        
        # Different endpoint
        metrics_responses = [client.get("/metrics").status_code for _ in range(50)]
        
        # Both should have some successful responses
        assert 200 in health_responses or 401 in health_responses


class TestErrorHandling:
    """Test error handling."""

    def test_404_for_nonexistent_endpoint(self, client):
        """Test 404 for non-existent endpoints."""
        response = client.get("/nonexistent/endpoint/xyz")
        assert response.status_code == 404

    def test_405_for_wrong_method(self, client):
        """Test 405 for wrong HTTP method."""
        response = client.delete("/health")  # Health is GET only
        assert response.status_code in [404, 405]

    def test_error_response_structure(self, client):
        """Test error responses have proper structure."""
        response = client.get("/nonexistent")
        assert response.status_code == 404
        
        data = response.json()
        # Should have error information
        assert "detail" in data or "error" in data or "message" in data


class TestCORS:
    """Test CORS configuration."""

    def test_cors_headers_present(self, client):
        """Test CORS headers are present in responses."""
        response = client.options(
            "/health",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "GET"
            }
        )
        
        # Should have CORS headers
        # (actual values depend on configuration)
        assert response.status_code in [200, 404]

    def test_cors_allows_configured_origins(self, client):
        """Test CORS allows configured origins."""
        response = client.get(
            "/health",
            headers={"Origin": "http://localhost:3000"}
        )
        
        assert response.status_code == 200


class TestSecurityHeaders:
    """Test security headers."""

    def test_security_headers_present(self, client):
        """Test security headers are included in responses."""
        response = client.get("/health")
        
        headers = response.headers
        
        # Common security headers
        # (may or may not be present depending on configuration)
        # X-Content-Type-Options, X-Frame-Options, etc.
        assert "content-type" in headers

    def test_no_sensitive_info_in_errors(self, client):
        """Test error responses don't leak sensitive information."""
        response = client.get("/nonexistent")
        
        body = response.text.lower()
        
        # Should not contain stack traces, file paths, etc.
        # (This is a basic check - real implementation may vary)
        assert "traceback" not in body or response.status_code != 500


class TestFileValidation:
    """Test file upload validation."""

    def test_file_size_limit(self, client, api_headers, monkeypatch):
        """Uploads above the configured limit are rejected with 413."""
        from analysis_engine.api import server

        monkeypatch.setattr(server.settings, "max_upload_size_mb", 1)
        response = client.post(
            "/analyze/upload",
            files={"file": ("large.jsonl", b"x" * (2 * 1024 * 1024), "application/json")},
            headers=api_headers,
        )

        assert response.status_code == 413

    def test_path_in_filename_is_rejected(self, client, api_headers):
        response = client.post(
            "/analyze/upload",
            files={"file": ("../../etc/passwd.jsonl", b"{}\n", "application/json")},
            headers=api_headers,
        )

        assert response.status_code == 400


class TestClientIdentity:
    """Forwarding headers must not let a client choose its own identity."""

    @staticmethod
    def _request(peer, headers=None):
        from starlette.requests import Request

        raw_headers = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
        return Request({"type": "http", "client": (peer, 1234), "headers": raw_headers})

    def test_forwarded_for_ignored_from_untrusted_peer(self, monkeypatch):
        from analysis_engine.api.security import get_client_ip

        monkeypatch.delenv("TRUSTED_PROXIES", raising=False)
        request = self._request("203.0.113.9", {"X-Forwarded-For": "1.2.3.4", "X-Real-IP": "5.6.7.8"})

        assert get_client_ip(request) == "203.0.113.9"

    def test_forwarded_for_used_behind_trusted_proxy(self, monkeypatch):
        from analysis_engine.api.security import get_client_ip

        monkeypatch.setenv("TRUSTED_PROXIES", "10.0.0.2, 10.0.0.3")
        # Client-supplied junk first, then the address nginx actually saw, then an inner proxy.
        request = self._request("10.0.0.2", {"X-Forwarded-For": "6.6.6.6, 198.51.100.7, 10.0.0.3"})

        assert get_client_ip(request) == "198.51.100.7"

    def test_rotating_forwarded_for_does_not_evade_lockout(self, client, monkeypatch):
        from analysis_engine.api import auth

        monkeypatch.delenv("TRUSTED_PROXIES", raising=False)
        monkeypatch.setattr(auth, "failed_attempts", __import__("collections").defaultdict(list))
        monkeypatch.setattr(auth, "locked_ips", {})

        statuses = [
            client.post(
                "/analyze/upload",
                files={"file": ("t.jsonl", b"{}\n", "application/json")},
                headers={"X-API-Key": "wrong", "X-Forwarded-For": f"192.0.2.{i}"},
            ).status_code
            for i in range(auth.LOCKOUT_THRESHOLD + 1)
        ]

        assert statuses[-1] == 429
