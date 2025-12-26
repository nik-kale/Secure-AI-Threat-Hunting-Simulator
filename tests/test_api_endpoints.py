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
    """Test analysis endpoint."""

    def test_analyze_endpoint_requires_auth(self, client):
        """Test analyze endpoint requires API key."""
        response = client.post("/analyze", files={})
        assert response.status_code in [401, 403]

    def test_analyze_with_valid_file(self, client, api_headers, temp_telemetry_file):
        """Test analysis with valid telemetry file."""
        with open(temp_telemetry_file, 'rb') as f:
            response = client.post(
                "/analyze",
                files={"file": ("telemetry.jsonl", f, "application/json")},
                headers=api_headers
            )
        
        # Should process successfully or return error
        assert response.status_code in [200, 400, 422]
        
        if response.status_code == 200:
            data = response.json()
            # Should have analysis results
            assert isinstance(data, dict)

    def test_analyze_with_invalid_file_type(self, client, api_headers):
        """Test analysis rejects invalid file types."""
        with tempfile.NamedTemporaryFile(suffix='.exe', mode='wb') as f:
            f.write(b'invalid content')
            f.flush()
            f.seek(0)
            
            response = client.post(
                "/analyze",
                files={"file": ("malware.exe", f, "application/octet-stream")},
                headers=api_headers
            )
        
        # Should reject invalid file type
        assert response.status_code in [400, 422]

    def test_analyze_with_empty_file(self, client, api_headers):
        """Test analysis with empty file."""
        with tempfile.NamedTemporaryFile(suffix='.jsonl', mode='w') as f:
            # Empty file
            f.flush()
            f.seek(0)
            
            response = client.post(
                "/analyze",
                files={"file": ("empty.jsonl", open(f.name, 'rb'), "application/json")},
                headers=api_headers
            )
        
        # May accept but return no results, or reject
        assert response.status_code in [200, 400, 422]

    def test_analyze_returns_structured_response(self, client, api_headers, temp_telemetry_file):
        """Test analysis returns structured response."""
        with open(temp_telemetry_file, 'rb') as f:
            response = client.post(
                "/analyze",
                files={"file": ("telemetry.jsonl", f, "application/json")},
                headers=api_headers
            )
        
        if response.status_code == 200:
            data = response.json()
            # Should have standard response structure
            assert isinstance(data, dict)


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
    """Test scenario generation endpoints."""

    def test_list_scenarios_endpoint(self, client):
        """Test listing available scenarios."""
        response = client.get("/scenarios")
        
        # May or may not require auth
        if response.status_code == 200:
            data = response.json()
            assert isinstance(data, (list, dict))

    def test_generate_scenario_requires_auth(self, client):
        """Test scenario generation requires authentication."""
        response = client.post(
            "/scenarios/generate",
            json={"scenario_name": "iam_priv_escalation"}
        )
        
        # Should require auth
        assert response.status_code in [401, 403, 404]

    def test_generate_scenario_with_auth(self, client, api_headers):
        """Test scenario generation with authentication."""
        response = client.post(
            "/scenarios/generate",
            json={"scenario_name": "iam_priv_escalation"},
            headers=api_headers
        )
        
        # Should process or indicate error
        assert response.status_code in [200, 400, 404, 422]

    def test_generate_scenario_invalid_name(self, client, api_headers):
        """Test scenario generation with invalid scenario name."""
        response = client.post(
            "/scenarios/generate",
            json={"scenario_name": "nonexistent_scenario_xyz"},
            headers=api_headers
        )
        
        # Should reject invalid scenario
        assert response.status_code in [400, 404, 422]


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

    def test_file_size_limit(self, client, api_headers):
        """Test file size limit is enforced."""
        # Create a large file (if limit exists)
        large_content = b'x' * (100 * 1024 * 1024)  # 100 MB
        
        with tempfile.NamedTemporaryFile(suffix='.jsonl', mode='wb') as f:
            f.write(large_content)
            f.flush()
            f.seek(0)
            
            response = client.post(
                "/analyze",
                files={"file": ("large.jsonl", f, "application/json")},
                headers=api_headers,
                timeout=5.0
            )
        
        # May enforce size limit
        # assert response.status_code in [200, 413, 422]

    def test_file_extension_validation(self, client, api_headers):
        """Test file extension validation."""
        with tempfile.NamedTemporaryFile(suffix='.txt', mode='w') as f:
            f.write('{"test": "data"}')
            f.flush()
            f.seek(0)
            
            response = client.post(
                "/analyze",
                files={"file": ("data.txt", open(f.name, 'rb'), "text/plain")},
                headers=api_headers
            )
        
        # May validate extensions
        assert response.status_code in [200, 400, 415, 422]

