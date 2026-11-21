"""Command execution against audit targets.

Every executor holds at most one session per host, which is reused for all
checks. Failures raise ExecutionError; there is deliberately no fallback that
returns placeholder text, because a check must never mistake "could not run"
for a result.
"""
from __future__ import annotations

import logging
import os
import shlex
import subprocess
import sys
from typing import Optional

from audit_tool.models import PLATFORMS, CommandResult

try:
    import paramiko  # type: ignore
except ImportError:  # pragma: no cover - exercised only without the dependency
    paramiko = None

try:
    import winrm  # type: ignore
except ImportError:  # pragma: no cover - exercised only without the dependency
    winrm = None

log = logging.getLogger(__name__)

LOCAL_HOSTNAMES = frozenset({"localhost", "127.0.0.1", "::1"})
TRANSPORTS = ("auto", "local", "ssh", "winrm")
# Never passed on to commands run by LocalExecutor.
SECRET_ENV_VARS = frozenset({"AUDIT_PASSWORD", "AUDIT_WEB_PASSWORD"})
WINRM_TRANSPORTS = ("ntlm", "kerberos", "credssp", "basic")

# Keeps PowerShell progress records out of stderr and makes output UTF-8.
_PS_PREAMBLE = (
    "$ProgressPreference='SilentlyContinue'; "
    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
)


class ExecutionError(Exception):
    """A command could not be run (connection, auth, timeout, missing tool)."""


def current_platform() -> str:
    return "windows" if sys.platform.startswith("win") else "linux"


class Executor:
    """Base interface. Use as a context manager so sessions are closed."""

    host: str = ""
    platform: str = ""

    def connect(self) -> None:
        """Open the session. Idempotent. Raises ExecutionError on failure."""

    def run(self, command: str, timeout: int = 60) -> CommandResult:
        raise NotImplementedError

    def close(self) -> None:
        """Release the session. Safe to call more than once."""

    def __enter__(self) -> "Executor":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


class LocalExecutor(Executor):
    """Runs checks on the machine the tool itself is running on."""

    def __init__(self, platform: Optional[str] = None) -> None:
        self.host = "localhost"
        self.platform = platform or current_platform()

    def run(self, command: str, timeout: int = 60) -> CommandResult:
        if self.platform == "windows":
            argv = ["powershell", "-NoProfile", "-NonInteractive", "-Command", _PS_PREAMBLE + command]
        else:
            argv = ["/bin/sh", "-c", command]
        log.debug("local: running %r", command)
        try:
            completed = subprocess.run(
                argv,
                capture_output=True,
                timeout=timeout,
                stdin=subprocess.DEVNULL,
                env={key: value for key, value in os.environ.items() if key not in SECRET_ENV_VARS},
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ExecutionError(f"command timed out after {timeout}s") from exc
        except OSError as exc:
            raise ExecutionError(f"could not start {argv[0]}: {exc}") from exc
        return CommandResult(
            exit_code=completed.returncode,
            stdout=completed.stdout.decode("utf-8", errors="replace"),
            stderr=completed.stderr.decode("utf-8", errors="replace"),
        )


class SSHExecutor(Executor):
    """Runs checks on a Linux host over a single reused Paramiko session.

    Host keys are verified against the user's known_hosts. Unknown hosts are
    rejected unless accept_unknown_host_keys is set explicitly.
    """

    def __init__(
        self,
        host: str,
        port: int = 22,
        username: Optional[str] = None,
        password: Optional[str] = None,
        key_file: Optional[str] = None,
        accept_unknown_host_keys: bool = False,
        connect_timeout: int = 10,
    ) -> None:
        self.host = host
        self.platform = "linux"
        self.port = port
        self.username = username
        self.password = password
        self.key_file = key_file
        self.accept_unknown_host_keys = accept_unknown_host_keys
        self.connect_timeout = connect_timeout
        self._client = None

    def connect(self) -> None:
        if self._client is not None:
            return
        if paramiko is None:
            raise ExecutionError("paramiko is not installed; install it with 'pip install paramiko'")
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        if self.accept_unknown_host_keys:
            log.warning("Accepting unknown SSH host key for %s; this is vulnerable to MITM", self.host)
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        try:
            client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                key_filename=self.key_file,
                timeout=self.connect_timeout,
                auth_timeout=self.connect_timeout,
                banner_timeout=self.connect_timeout,
                allow_agent=True,
                look_for_keys=True,
            )
        except paramiko.SSHException as exc:
            client.close()
            message = f"SSH connection to {self.host}:{self.port} failed: {exc}"
            if "known_hosts" in str(exc):
                message += (
                    " (add the host key with 'ssh-keyscan' or connect once with ssh, "
                    "or pass --accept-unknown-host-keys if you accept the MITM risk)"
                )
            raise ExecutionError(message) from exc
        except OSError as exc:
            client.close()
            raise ExecutionError(f"SSH connection to {self.host}:{self.port} failed: {exc}") from exc
        self._client = client

    def run(self, command: str, timeout: int = 60) -> CommandResult:
        self.connect()
        # Run through /bin/sh so checks don't depend on the remote login shell.
        wrapped = f"/bin/sh -c {shlex.quote(command)}"
        log.debug("ssh %s: running %r", self.host, command)
        try:
            stdin, stdout, stderr = self._client.exec_command(wrapped, timeout=timeout)
            stdin.close()
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            exit_code = stdout.channel.recv_exit_status()
        except (paramiko.SSHException, OSError) as exc:
            raise ExecutionError(f"command failed on {self.host}: {str(exc) or 'timed out'}") from exc
        return CommandResult(exit_code=exit_code, stdout=out, stderr=err)

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None


class WinRMExecutor(Executor):
    """Runs PowerShell checks on a Windows host over a single WinRM session.

    The per-command timeout is applied session-wide (WinRM operation timeout),
    so it is taken at construction time rather than per run() call.
    """

    def __init__(
        self,
        host: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        port: Optional[int] = None,
        https: bool = False,
        transport: str = "ntlm",
        command_timeout: int = 60,
    ) -> None:
        if transport not in WINRM_TRANSPORTS:
            raise ValueError(f"Unsupported WinRM transport {transport!r}")
        self.host = host
        self.platform = "windows"
        self.username = username
        self.password = password
        self.https = https
        self.port = port or (5986 if https else 5985)
        self.transport = transport
        self.command_timeout = command_timeout
        self._session = None

    @property
    def endpoint(self) -> str:
        scheme = "https" if self.https else "http"
        return f"{scheme}://{self.host}:{self.port}/wsman"

    def connect(self) -> None:
        if self._session is not None:
            return
        if winrm is None:
            raise ExecutionError("pywinrm is not installed; install it with 'pip install pywinrm'")
        if self.transport != "kerberos" and not (self.username and self.password):
            raise ExecutionError(
                f"WinRM {self.transport} authentication requires --username and the AUDIT_PASSWORD environment variable"
            )
        if self.transport == "basic" and not self.https:
            raise ExecutionError("Refusing to send Basic credentials over unencrypted HTTP; use --winrm-https")
        session = winrm.Session(
            self.endpoint,
            auth=(self.username or "", self.password or ""),
            transport=self.transport,
            server_cert_validation="validate",
            operation_timeout_sec=self.command_timeout,
            read_timeout_sec=self.command_timeout + 10,
        )
        # WinRM sessions are lazy; probe so connection/auth errors surface now.
        try:
            probe = session.run_ps("$PSVersionTable.PSVersion.Major")
        except Exception as exc:  # pywinrm/requests raise many unrelated types
            raise ExecutionError(f"WinRM connection to {self.endpoint} failed: {exc}") from exc
        if probe.status_code != 0:
            raise ExecutionError(f"WinRM probe on {self.endpoint} failed: {probe.std_err!r}")
        self._session = session

    def run(self, command: str, timeout: int = 60) -> CommandResult:
        self.connect()
        log.debug("winrm %s: running %r", self.host, command)
        try:
            result = self._session.run_ps(_PS_PREAMBLE + command)
        except Exception as exc:
            raise ExecutionError(f"command failed on {self.host}: {exc}") from exc
        return CommandResult(
            exit_code=result.status_code,
            stdout=(result.std_out or b"").decode("utf-8", errors="replace"),
            stderr=(result.std_err or b"").decode("utf-8", errors="replace"),
        )

    def close(self) -> None:
        self._session = None


def build_executor(
    host: str,
    platform: Optional[str] = None,
    transport: str = "auto",
    username: Optional[str] = None,
    password: Optional[str] = None,
    port: Optional[int] = None,
    key_file: Optional[str] = None,
    accept_unknown_host_keys: bool = False,
    winrm_transport: str = "ntlm",
    winrm_https: bool = False,
    command_timeout: int = 60,
) -> Executor:
    """Pick and configure an executor. Raises ValueError for invalid combinations.

    transport="auto" means: local execution for localhost, SSH for Linux
    targets and WinRM for Windows targets.
    """
    if transport not in TRANSPORTS:
        raise ValueError(f"Unknown transport {transport!r}; choose from {', '.join(TRANSPORTS)}")
    if platform is not None and platform not in PLATFORMS:
        raise ValueError(f"Unknown platform {platform!r}; choose from {', '.join(PLATFORMS)}")

    if transport == "auto":
        if host in LOCAL_HOSTNAMES:
            transport = "local"
        elif platform == "windows":
            transport = "winrm"
        elif platform == "linux":
            transport = "ssh"
        else:
            raise ValueError("--platform is required for remote hosts unless --transport is given")

    if transport == "local":
        local = current_platform()
        if platform is not None and platform != local:
            raise ValueError(f"Cannot audit a {platform} platform locally; this machine runs {local}")
        return LocalExecutor(platform=local)

    if transport == "ssh":
        if platform == "windows":
            raise ValueError("SSH transport supports Linux targets only; use --transport winrm for Windows")
        return SSHExecutor(
            host=host,
            port=port or 22,
            username=username,
            password=password,
            key_file=key_file,
            accept_unknown_host_keys=accept_unknown_host_keys,
        )

    if platform == "linux":
        raise ValueError("WinRM transport supports Windows targets only; use --transport ssh for Linux")
    return WinRMExecutor(
        host=host,
        username=username,
        password=password,
        port=port,
        https=winrm_https,
        transport=winrm_transport,
        command_timeout=command_timeout,
    )
