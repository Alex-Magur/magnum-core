"""Shared test fixtures for Phase Gate acceptance tests.

ADR Б0.9: No code merges to main without 100% Acceptance Criteria pass.
"""

import pytest


@pytest.fixture
def job_id() -> str:
    """Generate a test job_id."""
    return "test-job-001"
