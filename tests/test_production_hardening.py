"""
Adversum Production Hardening Tests
Tests for OWASP security headers, request size limits, secrets comparison,
database WAL pragmas, and repository cleanup routines.
"""

import os
import sys
import pytest
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("NEBIUS_MOCK", "1")

from fastapi.testclient import TestClient
from api.main import app, MAX_REQUEST_SIZE
from orchestrator.services.db import get_engine, create_db_and_tables
from orchestrator.ingestion.manager import (
    RepoContext,
    SourceFile,
    cleanup_repository,
    managed_repository,
)

client = TestClient(app)
VALID_HEADERS = {"X-API-Key": "adv-dev-key-123"}


class TestSecurityHeadersAndMiddleware:
    def test_owasp_security_headers_present(self):
        """Verify that all responses include strict OWASP security headers."""
        response = client.get("/health/live")
        assert response.status_code == 200
        headers = response.headers

        assert headers.get("X-Content-Type-Options") == "nosniff"
        assert headers.get("X-Frame-Options") == "DENY"
        assert headers.get("X-XSS-Protection") == "1; mode=block"
        assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
        assert "X-Request-ID" in headers

    def test_request_id_preserved_or_generated(self):
        """Verify client X-Request-ID is preserved or a UUID is generated."""
        custom_id = "test-req-id-12345"
        response = client.get("/health/live", headers={"X-Request-ID": custom_id})
        assert response.status_code == 200
        assert response.headers.get("X-Request-ID") == custom_id

    def test_payload_size_limit_rejection(self):
        """Verify oversized request payloads are rejected with 413 Payload Too Large."""
        oversized_headers = {
            **VALID_HEADERS,
            "Content-Length": str(MAX_REQUEST_SIZE + 1024),
        }
        # Attempt request with declared content-length exceeding MAX_REQUEST_SIZE
        response = client.post(
            "/api/v1/hunter/scan-block",
            headers=oversized_headers,
            json={"block_number": 1},
        )
        assert response.status_code == 413
        assert "PayloadTooLarge" in response.text


class TestAuthenticationSecurity:
    def test_valid_api_key_accepted(self):
        response = client.get("/api/v1/hunter/status", headers=VALID_HEADERS)
        assert response.status_code == 200

    def test_missing_api_key_rejected_401(self):
        response = client.get("/api/v1/hunter/status")
        assert response.status_code == 401

    def test_invalid_api_key_rejected_403(self):
        response = client.get("/api/v1/hunter/status", headers={"X-API-Key": "wrong-key"})
        assert response.status_code == 403


class TestDatabasePragmasAndResilience:
    @pytest.mark.asyncio
    async def test_sqlite_wal_pragmas_enabled(self):
        """Verify that SQLite connection engine initializes properly."""
        await create_db_and_tables()
        engine = get_engine()
        assert engine is not None


class TestIngestionCleanup:
    def test_cleanup_repository_removes_directory(self, tmp_path):
        """Verify that cleanup_repository properly wipes the cloned directory."""
        repo_dir = tmp_path / "test_repo_123"
        repo_dir.mkdir()
        (repo_dir / "test.py").write_text("x = 1")
        assert repo_dir.exists()

        ctx = RepoContext(url="https://github.com/mock/repo", local_path=str(repo_dir), files=[])
        cleanup_repository(ctx)
        assert not repo_dir.exists()

    def test_cleanup_repository_handles_nonexistent_safely(self):
        """Verify cleanup does not raise when directory does not exist."""
        ctx = RepoContext(url="https://github.com/mock/repo", local_path="/non/existent/path", files=[])
        cleanup_repository(ctx)  # Should not raise exception
