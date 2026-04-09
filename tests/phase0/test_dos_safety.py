"""P0-AC3: DoS Safety.

When: sampling receives 1MB input.
Then: max_sampling_input_bytes (256KB) enforces deterministic rejection.
"""

import pytest

pytestmark = pytest.mark.phase0
