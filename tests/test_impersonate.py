"""Unit tests for per-call impersonated subprocess execution.

Mirrors voms-token-service's test_minting.py pattern
(monkeypatch os.geteuid + the subprocess-launching call, record the kwargs
it was invoked with) since real setuid impersonation needs actual root
privilege and multiple real users, neither available in a unit-test sandbox.
"""

from __future__ import annotations

import asyncio
import sys
from typing import Any

import pytest

from af_filesystem_mcp import impersonate
from af_filesystem_mcp.impersonate import HelperError, HelperTimeoutError, run_helper


class _FakeProcess:
    def __init__(
        self,
        stdout: bytes = b"{}",
        stderr: bytes = b"",
        returncode: int = 0,
        delay: float = 0.0,
    ) -> None:
        self.stdout_bytes = stdout
        self.stderr_bytes = stderr
        self.returncode = returncode
        self._delay = delay
        self.killed = False

    async def communicate(self) -> tuple[bytes, bytes]:
        if self._delay:
            await asyncio.sleep(self._delay)
        return self.stdout_bytes, self.stderr_bytes

    def kill(self) -> None:
        self.killed = True

    async def wait(self) -> int:
        return self.returncode


class TestImpersonationWhenRoot:
    async def test_runs_helper_with_user_and_group_when_root(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        recorded: dict[str, Any] = {}

        async def fake_create_subprocess_exec(
            *argv: str, **kwargs: Any
        ) -> _FakeProcess:
            recorded["argv"] = argv
            recorded.update(kwargs)
            return _FakeProcess(stdout=b'{"ok": true}')

        monkeypatch.setattr(impersonate.os, "geteuid", lambda: 0)
        monkeypatch.setattr(
            impersonate.asyncio,
            "create_subprocess_exec",
            fake_create_subprocess_exec,
        )

        result = await run_helper(["list", "{}"], uid=4321, gid=8765, timeout=5.0)

        assert result == b'{"ok": true}'
        assert recorded["user"] == 4321
        assert recorded["group"] == 8765
        assert recorded["extra_groups"] == []
        assert recorded["argv"][0] == sys.executable
        assert recorded["argv"][1:4] == ("-m", "af_filesystem_mcp.helper", "list")
        assert recorded["argv"][4] == "{}"

    async def test_passes_through_explicit_extra_groups(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        recorded: dict[str, Any] = {}

        async def fake_create_subprocess_exec(
            *_argv: str, **kwargs: Any
        ) -> _FakeProcess:
            recorded.update(kwargs)
            return _FakeProcess()

        monkeypatch.setattr(impersonate.os, "geteuid", lambda: 0)
        monkeypatch.setattr(
            impersonate.asyncio,
            "create_subprocess_exec",
            fake_create_subprocess_exec,
        )

        await run_helper(
            ["stat", "{}"], uid=1, gid=2, timeout=5.0, extra_groups=[100, 200]
        )

        assert recorded["extra_groups"] == [100, 200]


class TestNoImpersonationWhenNotRoot:
    async def test_no_user_group_kwargs_when_not_root(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        recorded: dict[str, Any] = {}

        async def fake_create_subprocess_exec(
            *_argv: str, **kwargs: Any
        ) -> _FakeProcess:
            recorded.update(kwargs)
            return _FakeProcess()

        monkeypatch.setattr(impersonate.os, "geteuid", lambda: 1000)
        monkeypatch.setattr(
            impersonate.asyncio,
            "create_subprocess_exec",
            fake_create_subprocess_exec,
        )

        await run_helper(["list", "{}"], uid=4321, gid=8765, timeout=5.0)

        assert "user" not in recorded
        assert "group" not in recorded
        assert "extra_groups" not in recorded


class TestHelperErrorHandling:
    async def test_nonzero_exit_raises_helper_error_with_stderr(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def fake_create_subprocess_exec(
            *_argv: str, **_kwargs: Any
        ) -> _FakeProcess:
            return _FakeProcess(returncode=3, stderr=b"boom: permission denied")

        monkeypatch.setattr(impersonate.os, "geteuid", lambda: 0)
        monkeypatch.setattr(
            impersonate.asyncio,
            "create_subprocess_exec",
            fake_create_subprocess_exec,
        )

        with pytest.raises(HelperError, match="permission denied"):
            await run_helper(["read", "{}"], uid=1, gid=1, timeout=5.0)

    async def test_timeout_kills_process_and_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_proc = _FakeProcess(delay=10.0)

        async def fake_create_subprocess_exec(
            *_argv: str, **_kwargs: Any
        ) -> _FakeProcess:
            return fake_proc

        monkeypatch.setattr(impersonate.os, "geteuid", lambda: 0)
        monkeypatch.setattr(
            impersonate.asyncio,
            "create_subprocess_exec",
            fake_create_subprocess_exec,
        )

        with pytest.raises(HelperTimeoutError):
            await run_helper(["grep", "{}"], uid=1, gid=1, timeout=0.01)

        assert fake_proc.killed is True

    async def test_malformed_json_output_raises_helper_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def fake_create_subprocess_exec(
            *_argv: str, **_kwargs: Any
        ) -> _FakeProcess:
            return _FakeProcess(stdout=b"not json")

        monkeypatch.setattr(impersonate.os, "geteuid", lambda: 0)
        monkeypatch.setattr(
            impersonate.asyncio,
            "create_subprocess_exec",
            fake_create_subprocess_exec,
        )

        with pytest.raises(HelperError):
            await impersonate.run_helper_json(["list", "{}"], uid=1, gid=1, timeout=5.0)
