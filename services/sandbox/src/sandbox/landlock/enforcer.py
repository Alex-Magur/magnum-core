"""sandbox.landlock.enforcer — Linux Landlock API for filesystem isolation.

ADR Блок 3.1: Linux Landlock is a hard requirement for isolating the sandbox
to reading/writing strictly within the /workspace directory.
"""

from __future__ import annotations

import ctypes
import errno
import logging
import os
import platform
from pathlib import Path
from typing import Final

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Syscall Numbers (x86_64 / aarch64 common)
# ---------------------------------------------------------------------------

_SYS_LANDLOCK_CREATE_RULESET: Final[int] = 444
_SYS_LANDLOCK_ADD_RULE: Final[int] = 445
_SYS_LANDLOCK_RESTRICT_SELF: Final[int] = 446

_PR_SET_NO_NEW_PRIVS: Final[int] = 38

# ---------------------------------------------------------------------------
# Landlock Constants
# ---------------------------------------------------------------------------

_LANDLOCK_RULE_PATH_BENEATH: Final[int] = 1

# Access flags (ABI v1)
_LANDLOCK_ACCESS_FS_EXECUTE: Final[int] = 1 << 0
_LANDLOCK_ACCESS_FS_WRITE_FILE: Final[int] = 1 << 1
_LANDLOCK_ACCESS_FS_READ_FILE: Final[int] = 1 << 2
_LANDLOCK_ACCESS_FS_READ_DIR: Final[int] = 1 << 3
_LANDLOCK_ACCESS_FS_REMOVE_DIR: Final[int] = 1 << 4
_LANDLOCK_ACCESS_FS_REMOVE_FILE: Final[int] = 1 << 5
_LANDLOCK_ACCESS_FS_MAKE_CHAR: Final[int] = 1 << 6
_LANDLOCK_ACCESS_FS_MAKE_DIR: Final[int] = 1 << 7
_LANDLOCK_ACCESS_FS_MAKE_REG: Final[int] = 1 << 8
_LANDLOCK_ACCESS_FS_MAKE_SOCK: Final[int] = 1 << 9
_LANDLOCK_ACCESS_FS_MAKE_FIFO: Final[int] = 1 << 10
_LANDLOCK_ACCESS_FS_MAKE_BLOCK: Final[int] = 1 << 11
_LANDLOCK_ACCESS_FS_MAKE_SYM: Final[int] = 1 << 12

_ALL_FS_ACCESS: Final[int] = (
    _LANDLOCK_ACCESS_FS_EXECUTE
    | _LANDLOCK_ACCESS_FS_WRITE_FILE
    | _LANDLOCK_ACCESS_FS_READ_FILE
    | _LANDLOCK_ACCESS_FS_READ_DIR
    | _LANDLOCK_ACCESS_FS_REMOVE_DIR
    | _LANDLOCK_ACCESS_FS_REMOVE_FILE
    | _LANDLOCK_ACCESS_FS_MAKE_CHAR
    | _LANDLOCK_ACCESS_FS_MAKE_DIR
    | _LANDLOCK_ACCESS_FS_MAKE_REG
    | _LANDLOCK_ACCESS_FS_MAKE_SOCK
    | _LANDLOCK_ACCESS_FS_MAKE_FIFO
    | _LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | _LANDLOCK_ACCESS_FS_MAKE_SYM
)


# ---------------------------------------------------------------------------
# C Structs
# ---------------------------------------------------------------------------

class LandlockRulesetAttr(ctypes.Structure):
    """struct landlock_ruleset_attr"""

    _fields_ = [
        ("handled_access_fs", ctypes.c_uint64),
    ]


class LandlockPathBeneathAttr(ctypes.Structure):
    """struct landlock_path_beneath_attr"""

    _pack_ = 1  # Packed structure
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    ]


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

class LandlockUnavailableError(RuntimeError):
    """Raised when Landlock is unavailable (ADR Блок 3.1 hard requirement)."""


class LandlockEnforcer:
    """Isolates the current process to a specific workspace directory using Landlock."""

    def __init__(self, workspace: str | Path) -> None:
        self.workspace = Path(workspace).resolve()

    def apply(self) -> None:
        """Apply Landlock restrictions.

        Raises:
            LandlockUnavailableError: If Landlock is not supported by the kernel.
            OSError: For other unexpected system errors.
        """
        if platform.system() != "Linux":
            raise LandlockUnavailableError("Landlock is only supported on Linux.")

        libc = ctypes.CDLL(None, use_errno=True)

        # 1. Create Ruleset
        attr = LandlockRulesetAttr(handled_access_fs=_ALL_FS_ACCESS)

        # ABI v1 (flags=0)
        ruleset_fd = libc.syscall(
            _SYS_LANDLOCK_CREATE_RULESET,
            ctypes.byref(attr),
            ctypes.sizeof(attr),
            0,
        )

        if ruleset_fd < 0:
            err = ctypes.get_errno()
            if err in (errno.ENOSYS, errno.EOPNOTSUPP, errno.EPERM):
                raise LandlockUnavailableError(f"Kernel lacks Landlock support or access is blocked (errno {err}).")
            raise OSError(err, os.strerror(err))

        try:
            # 2. Add Rule for the workspace
            try:
                parent_fd = os.open(self.workspace, os.O_PATH | os.O_CLOEXEC)
            except OSError as e:
                raise RuntimeError(
                    f"Cannot open workspace '{self.workspace}' for Landlock rule."
                ) from e

            try:
                path_attr = LandlockPathBeneathAttr(
                    allowed_access=_ALL_FS_ACCESS,
                    parent_fd=parent_fd,
                )

                res = libc.syscall(
                    _SYS_LANDLOCK_ADD_RULE,
                    ruleset_fd,
                    _LANDLOCK_RULE_PATH_BENEATH,
                    ctypes.byref(path_attr),
                    0,
                )

                if res < 0:
                    err = ctypes.get_errno()
                    raise OSError(err, os.strerror(err))
            finally:
                os.close(parent_fd)

            # 3. Restrict Self
            # Must set PR_SET_NO_NEW_PRIVS first (required by Landlock)
            if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
                err = ctypes.get_errno()
                raise OSError(err, os.strerror(err))

            res = libc.syscall(
                _SYS_LANDLOCK_RESTRICT_SELF,
                ruleset_fd,
                0,
            )

            if res < 0:
                err = ctypes.get_errno()
                raise OSError(err, os.strerror(err))

        finally:
            os.close(ruleset_fd)

        logger.info(
            "Landlock successfully applied. Strict isolation enforced on %s",
            self.workspace,
        )


def apply_landlock(workspace_path: str | Path) -> None:
    """Helper wrapper to quickly apply Landlock isolation."""
    enforcer = LandlockEnforcer(workspace_path)
    enforcer.apply()
