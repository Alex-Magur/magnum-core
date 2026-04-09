"""P0-AC2: Security Coverage.

When: injection test suite runs.
Then: each battery records outcome: BLOCK/QUARANTINE/ALLOW.
"""

import pytest

pytestmark = pytest.mark.phase0
