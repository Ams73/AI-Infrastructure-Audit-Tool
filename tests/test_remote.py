import unittest

from audit_tool.remote import RemoteConnection, RemoteExecutor


class RemoteExecutorTests(unittest.TestCase):
    def test_linux_executor_returns_placeholder_when_ssh_unavailable(self):
        executor = RemoteExecutor(RemoteConnection(host="example", platform="linux"))
        output = executor.run_command("uname")
        self.assertIn("ssh", output.lower())

    def test_windows_executor_returns_placeholder(self):
        executor = RemoteExecutor(RemoteConnection(host="example", platform="windows"))
        output = executor.run_command("Get-Host")
        self.assertIn("windows", output.lower())


if __name__ == "__main__":
    unittest.main()
