import time
import unittest
from types import SimpleNamespace
from unittest import mock

import paramiko

from audit_tool.executors import (
    ExecutionError,
    LocalExecutor,
    SSHExecutor,
    WinRMExecutor,
    build_executor,
    current_platform,
)


class LocalExecutorTests(unittest.TestCase):
    def test_runs_command_and_captures_output(self):
        result = LocalExecutor().run("echo hello", timeout=30)
        self.assertEqual(result.exit_code, 0)
        self.assertIn("hello", result.stdout)

    def test_reports_nonzero_exit_code(self):
        self.assertEqual(LocalExecutor().run("exit 3", timeout=30).exit_code, 3)

    def test_secrets_are_not_passed_to_commands(self):
        if current_platform() == "windows":
            command = 'Write-Output "[$env:AUDIT_PASSWORD][$env:AUDIT_WEB_PASSWORD][$env:AUDIT_TEST_VISIBLE]"'
        else:
            command = 'echo "[$AUDIT_PASSWORD][$AUDIT_WEB_PASSWORD][$AUDIT_TEST_VISIBLE]"'
        env = {"AUDIT_PASSWORD": "s3cret", "AUDIT_WEB_PASSWORD": "web-s3cret", "AUDIT_TEST_VISIBLE": "visible"}
        with mock.patch.dict("os.environ", env):
            output = LocalExecutor().run(command, timeout=30).stdout
        self.assertIn("[][][visible]", output)

    def test_timeout_raises_execution_error(self):
        command = "Start-Sleep -Seconds 10" if current_platform() == "windows" else "sleep 10"
        with self.assertRaises(ExecutionError):
            LocalExecutor().run(command, timeout=1)


class BuildExecutorTests(unittest.TestCase):
    def test_localhost_uses_local_executor_for_this_os(self):
        executor = build_executor("localhost")
        self.assertIsInstance(executor, LocalExecutor)
        self.assertEqual(executor.platform, current_platform())

    def test_remote_transport_follows_platform(self):
        self.assertIsInstance(build_executor("web01", platform="linux"), SSHExecutor)
        winrm_executor = build_executor("win01", platform="windows", winrm_https=True)
        self.assertIsInstance(winrm_executor, WinRMExecutor)
        self.assertEqual(winrm_executor.endpoint, "https://win01:5986/wsman")

    def test_invalid_combinations_are_rejected(self):
        other = "linux" if current_platform() == "windows" else "windows"
        cases = [
            dict(host="web01"),  # remote host without platform
            dict(host="web01", platform="windows", transport="ssh"),
            dict(host="web01", platform="linux", transport="winrm"),
            dict(host="localhost", platform=other),
            dict(host="web01", platform="solaris"),
            dict(host="web01", platform="linux", transport="telnet"),
        ]
        for kwargs in cases:
            with self.subTest(**kwargs), self.assertRaises(ValueError):
                build_executor(**kwargs)


def _fake_paramiko():
    fake = mock.MagicMock()
    fake.SSHException = paramiko.SSHException
    return fake


class SSHExecutorTests(unittest.TestCase):
    def test_unknown_host_keys_are_rejected_by_default(self):
        fake = _fake_paramiko()
        with mock.patch("audit_tool.executors.paramiko", fake):
            SSHExecutor("web01").connect()
        client = fake.SSHClient.return_value
        client.load_system_host_keys.assert_called_once()
        client.set_missing_host_key_policy.assert_called_once_with(fake.RejectPolicy.return_value)

    def test_accepting_unknown_host_keys_requires_opt_in(self):
        fake = _fake_paramiko()
        with mock.patch("audit_tool.executors.paramiko", fake):
            SSHExecutor("web01", accept_unknown_host_keys=True).connect()
        fake.SSHClient.return_value.set_missing_host_key_policy.assert_called_once_with(
            fake.AutoAddPolicy.return_value
        )

    def test_host_key_failure_explains_fix(self):
        fake = _fake_paramiko()
        fake.SSHClient.return_value.connect.side_effect = paramiko.SSHException(
            "Server 'web01' not found in known_hosts"
        )
        with mock.patch("audit_tool.executors.paramiko", fake):
            with self.assertRaises(ExecutionError) as ctx:
                SSHExecutor("web01").connect()
        self.assertIn("ssh-keyscan", str(ctx.exception))

    def test_network_failure_raises_execution_error(self):
        fake = _fake_paramiko()
        fake.SSHClient.return_value.connect.side_effect = ConnectionRefusedError("refused")
        with mock.patch("audit_tool.executors.paramiko", fake):
            with self.assertRaises(ExecutionError):
                SSHExecutor("web01").connect()

    def run_with_channels(self, *channels, timeout=30):
        fake = _fake_paramiko()
        client = fake.SSHClient.return_value
        client.get_transport.return_value.open_session.side_effect = list(channels)
        with mock.patch("audit_tool.executors.paramiko", fake):
            executor = SSHExecutor("web01")
            results = []
            for _ in channels:
                try:
                    results.append(executor.run("echo 'a b'", timeout=timeout))
                except ExecutionError as exc:
                    results.append(exc)
            executor.close()
        return fake, client, results

    def test_session_is_reused_and_commands_run_via_sh(self):
        fake, client, results = self.run_with_channels(
            FakeChannel(stdout=b"out", stderr=b"err", exit_code=2), FakeChannel(stdout=b"ok")
        )
        first = results[0]
        self.assertEqual(fake.SSHClient.call_count, 1)
        self.assertEqual((first.exit_code, first.stdout, first.stderr), (2, "out", "err"))
        self.assertEqual(results[1].stdout, "ok")
        self.assertEqual(client.get_transport.return_value.open_session.call_count, 2)
        client.close.assert_called_once()

    def test_command_is_quoted_for_sh_and_channel_is_closed(self):
        channel = FakeChannel(stdout=b"x")
        self.run_with_channels(channel)
        self.assertEqual(channel.command, "/bin/sh -c 'echo '\"'\"'a b'\"'\"''")
        self.assertTrue(channel.write_shut and channel.closed)

    def test_large_stderr_before_stdout_does_not_deadlock(self):
        # Models SSH flow control: stdout only arrives once stderr has been read.
        # Reading stdout to the end first (the old behavior) would wait forever.
        stderr = b"find: Permission denied\n" * 200_000  # ~4.8 MB
        channel = FakeChannel(stdout=b"result", stderr=stderr, stdout_after_stderr=True)
        _, _, results = self.run_with_channels(channel, timeout=10)
        self.assertEqual(results[0].stdout, "result")
        self.assertEqual(len(results[0].stderr), len(stderr))

    def test_overall_timeout_is_enforced(self):
        channel = FakeChannel(stdout=b"", never_finishes=True)
        started = time.monotonic()
        _, _, results = self.run_with_channels(channel, timeout=1)
        self.assertIsInstance(results[0], ExecutionError)
        self.assertIn("timed out after 1s", str(results[0]))
        self.assertLess(time.monotonic() - started, 5)
        self.assertTrue(channel.closed)

    def test_dropped_connection_fails_fast(self):
        channel = FakeChannel(stdout=b"", dropped=True)
        _, _, results = self.run_with_channels(channel, timeout=30)
        self.assertIsInstance(results[0], ExecutionError)
        self.assertIn("closed before the command finished", str(results[0]))


class FakeChannel:
    """Minimal stand-in for paramiko.Channel's non-blocking read API."""

    def __init__(self, stdout=b"", stderr=b"", exit_code=0, stdout_after_stderr=False,
                 never_finishes=False, dropped=False):
        self._stdout, self._stderr = bytearray(stdout), bytearray(stderr)
        self._exit_code = exit_code
        self._stdout_after_stderr = stdout_after_stderr
        self._never_finishes = never_finishes
        self.command = None
        self.write_shut = False
        self.closed = dropped
        self._dropped = dropped
        self.eof_received = False

    def exec_command(self, command):
        self.command = command

    def shutdown_write(self):
        self.write_shut = True

    def recv_ready(self):
        if self._stdout_after_stderr and self._stderr:
            return False
        return bool(self._stdout)

    def recv(self, size):
        chunk, self._stdout[:] = bytes(self._stdout[:size]), self._stdout[size:]
        return chunk

    def recv_stderr_ready(self):
        return bool(self._stderr)

    def recv_stderr(self, size):
        chunk, self._stderr[:] = bytes(self._stderr[:size]), self._stderr[size:]
        return chunk

    def exit_status_ready(self):
        if self._never_finishes or self._dropped:
            return False
        done = not self._stdout and not self._stderr
        self.eof_received = done
        return done

    def recv_exit_status(self):
        return self._exit_code

    def close(self):
        self.closed = True


def _ps_result(code=0, out=b"5", err=b""):
    return SimpleNamespace(status_code=code, std_out=out, std_err=err)


class WinRMExecutorTests(unittest.TestCase):
    def test_requires_credentials_for_ntlm(self):
        with mock.patch("audit_tool.executors.winrm", mock.MagicMock()):
            with self.assertRaises(ExecutionError):
                WinRMExecutor("win01", username="admin").connect()

    def test_refuses_basic_auth_over_http(self):
        with mock.patch("audit_tool.executors.winrm", mock.MagicMock()):
            with self.assertRaises(ExecutionError):
                WinRMExecutor("win01", username="a", password="p", transport="basic").connect()

    def test_probe_failure_raises_execution_error(self):
        fake = mock.MagicMock()
        fake.Session.return_value.run_ps.side_effect = Exception("401 Unauthorized")
        with mock.patch("audit_tool.executors.winrm", fake):
            with self.assertRaises(ExecutionError) as ctx:
                WinRMExecutor("win01", username="a", password="p").connect()
        self.assertIn("401", str(ctx.exception))

    def test_runs_powershell_with_validated_session(self):
        fake = mock.MagicMock()
        session = fake.Session.return_value
        session.run_ps.side_effect = [_ps_result(), _ps_result(1, b"", b"denied")]
        with mock.patch("audit_tool.executors.winrm", fake):
            result = WinRMExecutor("win01", username="a", password="p").run("Get-Thing")

        kwargs = fake.Session.call_args.kwargs
        self.assertEqual(kwargs["transport"], "ntlm")
        self.assertEqual(kwargs["server_cert_validation"], "validate")
        self.assertTrue(session.run_ps.call_args.args[0].endswith("Get-Thing"))
        self.assertEqual((result.exit_code, result.stderr), (1, "denied"))


if __name__ == "__main__":
    unittest.main()
