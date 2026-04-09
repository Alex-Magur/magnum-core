import os
import platform
import ctypes
import errno
from unittest.mock import MagicMock, patch
import pytest
from sandbox.landlock.enforcer import LandlockEnforcer, LandlockUnavailableError


@pytest.fixture
def mock_libc():
    with patch("ctypes.CDLL") as mock_cdll:
        libc = MagicMock()
        mock_cdll.return_value = libc
        yield libc


def test_enforcer_init():
    enforcer = LandlockEnforcer("/tmp/workspace")
    assert str(enforcer.workspace) == os.path.abspath("/tmp/workspace")


def test_enforcer_non_linux():
    with patch("platform.system", return_value="Darwin"):
        enforcer = LandlockEnforcer("/workspace")
        with pytest.raises(LandlockUnavailableError, match="only supported on Linux"):
            enforcer.apply()


def test_enforcer_apply_success(mock_libc):
    """Verify the full Landlock sequence is called correctly on success."""
    with patch("platform.system", return_value="Linux"), \
         patch("os.open", return_value=10), \
         patch("os.close") as mock_close, \
         patch("ctypes.byref", side_effect=lambda x: x), \
         patch("ctypes.sizeof", return_value=8):
        
        # Mock syscalls to return success (ruleset_fd=5, others=0)
        mock_libc.syscall.side_effect = [5, 0, 0]
        mock_libc.prctl.return_value = 0
        
        enforcer = LandlockEnforcer("/workspace")
        enforcer.apply()
        
        # Check syscall sequence: CREATE_RULESET, ADD_RULE, RESTRICT_SELF
        # _SYS_LANDLOCK_CREATE_RULESET = 444
        # _SYS_LANDLOCK_ADD_RULE = 445
        # _SYS_LANDLOCK_RESTRICT_SELF = 446
        assert mock_libc.syscall.call_count == 3
        assert mock_libc.syscall.call_args_list[0][0][0] == 444
        assert mock_libc.syscall.call_args_list[1][0][0] == 445
        assert mock_libc.syscall.call_args_list[2][0][0] == 446
        
        # Check prctl for NO_NEW_PRIVS (38)
        mock_libc.prctl.assert_called_once_with(38, 1, 0, 0, 0)


def test_enforcer_no_kernel_support(mock_libc):
    """Verify LandlockUnavailableError is raised if kernel lacks support."""
    with patch("platform.system", return_value="Linux"), \
         patch("ctypes.get_errno", return_value=errno.ENOSYS):
        
        mock_libc.syscall.return_value = -1 # Failure
        
        enforcer = LandlockEnforcer("/workspace")
        with pytest.raises(LandlockUnavailableError, match="Kernel lacks Landlock support"):
            enforcer.apply()
