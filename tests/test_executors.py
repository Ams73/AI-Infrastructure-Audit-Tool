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

    def test_session_is_reused_and_commands_run_via_sh(self):
        fake = _fake_paramiko()
        client = fake.SSHClient.return_value
        stdout = mock.MagicMock()
        stdout.read.return_value = b"out"
        stdout.channel.recv_exit_status.return_value = 2
        stderr = mock.MagicMock()
        stderr.read.return_value = b"err"
        client.exec_command.return_value = (mock.MagicMock(), stdout, stderr)

        with mock.patch("audit_tool.executors.paramiko", fake):
            executor = SSHExecutor("web01")
            first = executor.run("echo 'a b'")
            executor.run("true")
            executor.close()

        self.assertEqual(fake.SSHClient.call_count, 1)
        self.assertEqual((first.exit_code, first.stdout, first.stderr), (2, "out", "err"))
        self.assertEqual(client.exec_command.call_args_list[0].args[0], "/bin/sh -c 'echo '\"'\"'a b'\"'\"''")
        client.close.assert_called_once()


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
