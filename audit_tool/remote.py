from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Optional

# Optional imports for improved remote execution
try:
    import paramiko  # type: ignore
except Exception:
    paramiko = None

try:
    import winrm  # type: ignore
except Exception:
    winrm = None


@dataclass
class RemoteConnection:
    host: str
    username: Optional[str] = None
    password: Optional[str] = None
    port: int = 22
    platform: str = "linux"


class RemoteExecutor:
    def __init__(self, connection: RemoteConnection):
        self.connection = connection

    def run_command(self, command: str) -> str:
        """Run a command on the remote host.

        Tries Paramiko for SSH (Linux) and pywinrm for Windows. Falls back to
        system `ssh` command or a placeholder when unavailable.
        """
        if self.connection.platform == "windows":
            # Prefer WinRM if available
            if winrm is not None:
                try:
                    session = winrm.Session(self.connection.host, auth=(self.connection.username or "", self.connection.password or ""))
                    result = session.run_cmd(command)
                    stdout = (result.std_out or b"").decode(errors="ignore").strip()
                    stderr = (result.std_err or b"").decode(errors="ignore").strip()
                    if stderr:
                        return stderr
                    return stdout or "remote command completed"
                except Exception as e:
                    return f"winrm error: {e}"
            # Fallback placeholder
            return f"[windows] command prepared: {command}"

        # For Linux/SSH targets prefer paramiko
        if paramiko is not None:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                connect_kwargs = {"hostname": self.connection.host, "port": self.connection.port}
                if self.connection.username:
                    connect_kwargs["username"] = self.connection.username
                if self.connection.password:
                    connect_kwargs["password"] = self.connection.password
                client.connect(**connect_kwargs, timeout=5)
                stdin, stdout, stderr = client.exec_command(command, timeout=30)
                out = stdout.read().decode(errors="ignore").strip()
                err = stderr.read().decode(errors="ignore").strip()
                client.close()
                if err:
                    return err
                return out or "remote command completed"
            except Exception as e:
                # If paramiko fails, fall back to system ssh
                fallback_msg = f"paramiko error: {e}"

        # Fallback to system ssh
        if self.connection.username:
            target = f"{self.connection.username}@{self.connection.host}"
            full_command = ["ssh", "-p", str(self.connection.port), target, command]
        else:
            full_command = ["ssh", "-p", str(self.connection.port), self.connection.host, command]

        try:
            completed = subprocess.run(full_command, capture_output=True, text=True, check=False)
            if completed.returncode != 0:
                return completed.stderr.strip() or completed.stdout.strip() or "remote command failed"
            return completed.stdout.strip() or "remote command completed"
        except FileNotFoundError:
            # Provide any earlier paramiko error if present
            return locals().get("fallback_msg", "ssh command not available")
