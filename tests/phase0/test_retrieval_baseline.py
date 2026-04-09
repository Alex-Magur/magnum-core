"""P0-AC1: Retrieval Baseline.

Given: repo >= 500 files.
When: retrieval eval suite runs.
Then: publishes Recall@5, MRR@10, P95 latency.
"""

import pytest

pytestmark = pytest.mark.phase0
