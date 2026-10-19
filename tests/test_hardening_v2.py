"""
Adversum Security Hardening v2 Tests
Tests for: /metrics endpoint, Pydantic input validators, docker-compose security.
"""

import os
import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("NEBIUS_MOCK", "1")

from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)
VALID_HEADERS = {"X-API-Key": "adv-dev-key-123"}


class TestPrometheusMetrics:
    def test_metrics_endpoint_accessible_without_auth(self):
        """The /metrics endpoint must be accessible without API key (Prometheus scraping)."""
        response = client.get("/metrics")
        # Either 200 (prometheus_client installed) or 501 (not installed)
        assert response.status_code in (200, 501)

    def test_metrics_returns_prometheus_content_type(self):
        """When prometheus_client is installed, /metrics returns text/plain."""
        response = client.get("/metrics")
        if response.status_code == 200:
            assert "text/plain" in response.headers.get("content-type", "")

    def test_metrics_contains_standard_counter_names(self):
        """Verify standard Adversum metric names appear in the output."""
        response = client.get("/metrics")
        if response.status_code == 200:
            body = response.text
            # At least one Adversum metric should be defined
            assert "adversum_" in body


class TestPydanticInputValidation:
    def test_audit_request_blocks_path_traversal(self):
        """AuditRequest must reject paths containing '..'."""
        response = client.post(
            "/audit",
            headers=VALID_HEADERS,
            json={"target_path": "../../etc/passwd", "project_name": "evil"},
        )
        # 422 Unprocessable Entity from Pydantic validation
        assert response.status_code == 422

    def test_scan_request_rejects_invalid_severity(self):
        """ScanAllRequest must reject unknown min_severity values."""
        response = client.post(
            "/audit",
            headers=VALID_HEADERS,
            json={"target_path": "/tmp/test", "min_severity": "UNKNOWN_LEVEL"},
        )
        # Either 422 (validation) or 404/422 from routing — not 200
        assert response.status_code != 200 or "error" in response.text.lower()

    def test_audit_request_accepts_valid_path(self):
        """AuditRequest must accept a valid, safe path."""
        # This will kick off a background task but validation should not reject it
        response = client.post(
            "/audit",
            headers=VALID_HEADERS,
            json={"target_path": "/tmp/safe_repo", "project_name": "test_project"},
        )
        # Not a 422 — model validation passed
        assert response.status_code != 422

    def test_self_healing_pr_rejects_non_github_url(self):
        """SelfHealingPRRequest must reject non-GitHub/GitLab repo URLs."""
        response = client.post(
            "/api/v1/remediation/self-healing-pr",
            headers=VALID_HEADERS,
            json={
                "finding": {"id": "1", "file": "test.py", "line": 1, "rule_id": "X", "severity": "HIGH", "description": "test", "recommendation": "fix"},
                "repo_url": "http://evil.com/malicious",
                "apply_to_disk": False,
            },
        )
        assert response.status_code == 422

    def test_self_healing_pr_accepts_github_url(self):
        """SelfHealingPRRequest must accept a legitimate GitHub URL."""
        response = client.post(
            "/api/v1/remediation/self-healing-pr",
            headers=VALID_HEADERS,
            json={
                "finding": {"id": "1", "file": "test.py", "line": 1, "rule_id": "X", "severity": "HIGH", "description": "test", "recommendation": "fix"},
                "repo_url": "https://github.com/ibonon/Adversum",
                "apply_to_disk": False,
            },
        )
        # Should not be 422 (validation error) — might be 200 or other status
        assert response.status_code != 422
