import unittest

from audit_tool.remote import RemoteConnection, RemoteExecutor


class RemoteExecutionTests(unittest.TestCase):
    def test_linux_command_runner_uses_ssh_command(self):
        executor = RemoteExecutor(RemoteConnection(host="example", username="admin", platform="linux"))
        result = executor.run_command("uname")
        self.assertTrue(isinstance(result, str))

    def test_windows_command_runner_returns_placeholder_message(self):
        executor = RemoteExecutor(RemoteConnection(host="example", platform="windows"))
        result = executor.run_command("Get-Host")
        self.assertIn("windows", result.lower())


if __name__ == "__main__":
    unittest.main()
