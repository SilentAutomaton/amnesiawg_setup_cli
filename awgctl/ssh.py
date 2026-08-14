"""SSH transport: the system ssh binary, one shared connection per run.

Shelling out to ssh instead of using a library keeps ~/.ssh/config, ProxyJump,
ssh-agent, hardware keys and known_hosts working, and lets ssh itself ask for a
key passphrase. ControlMaster means it asks only once per run.
"""

from __future__ import annotations

import getpass
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

from .config import Server


class RemoteError(Exception):
    pass


class Ssh:
    def __init__(self, server: Server, verbose: bool = False):
        self.server = server
        self.verbose = verbose
        self._control_dir = tempfile.TemporaryDirectory(prefix="awgctl-")
        self._sudo_prefix: str | None = None
        self._sudo_password: str | None = None

    def __enter__(self) -> "Ssh":
        return self

    def __exit__(self, *_exc) -> None:
        self._control_dir.cleanup()

    def connect(self) -> None:
        """Open the shared connection with the terminal attached, so ssh can ask for
        a key passphrase or a host key confirmation before any output is captured."""
        if subprocess.run(self._ssh_args() + ["true"]).returncode != 0:
            raise RemoteError(f"cannot connect to {self.server.host}")

    def run(self, command: str, *, stdin: str = "", check: bool = True) -> str:
        result = self._exec(command, stdin)
        if check and result.returncode != 0:
            detail = (result.stderr.strip() or result.stdout.strip()).splitlines()
            raise RemoteError("\n".join([f"command failed: {command}"] + detail[-10:]))
        return result.stdout

    def ok(self, command: str) -> bool:
        return self._exec(command, "").returncode == 0

    def sudo(self, command: str, *, stdin: str = "", check: bool = True) -> str:
        prefix = self._privilege_prefix()
        if not prefix:
            return self.run(command, stdin=stdin, check=check)
        if self._sudo_password is not None:
            stdin = self._sudo_password + "\n" + stdin
        return self.run(f"{prefix} sh -c {shlex.quote(command)}", stdin=stdin, check=check)

    def sudo_ok(self, command: str) -> bool:
        try:
            self.sudo(command)
        except RemoteError:
            return False
        return True

    def put(self, data: str, path: str, mode: str = "600") -> None:
        quoted = shlex.quote(path)
        self.run(f"cat > {quoted} && chmod {mode} {quoted}", stdin=data)

    def get(self, path: str) -> str:
        return self.run(f"cat {shlex.quote(path)}")

    def exists(self, path: str) -> bool:
        return self.ok(f"test -e {shlex.quote(path)}")

    def _exec(self, command: str, stdin: str) -> subprocess.CompletedProcess:
        if self.verbose:
            print(f"$ {command}", file=sys.stderr)
        return subprocess.run(
            self._ssh_args() + [command],
            input=stdin,
            capture_output=True,
            text=True,
        )

    def _ssh_args(self) -> list[str]:
        socket = Path(self._control_dir.name) / "socket"
        args = [
            "ssh",
            "-o",
            "ControlMaster=auto",
            "-o",
            f"ControlPath={socket}",
            "-o",
            "ControlPersist=60s",
            "-o",
            "ConnectTimeout=10",
            "-p",
            str(self.server.port),
        ]
        if self.server.identity_file:
            args += ["-i", str(Path(self.server.identity_file).expanduser())]
        target = self.server.host
        if self.server.user:
            target = f"{self.server.user}@{target}"
        return args + [target]

    def _privilege_prefix(self) -> str:
        if self._sudo_prefix is None:
            self._sudo_prefix = self._probe_privilege()
        return self._sudo_prefix

    def _probe_privilege(self) -> str:
        mode = self.server.privilege
        if mode in ("none", "root"):
            return ""
        if mode == "auto" and self.ok("docker info"):
            return ""
        if self.ok("sudo -n true"):
            return "sudo -n"

        target = f"{self.server.user}@{self.server.host}" if self.server.user else self.server.host
        self._sudo_password = getpass.getpass(f"sudo password for {target}: ")
        prefix = "sudo -S -p ''"
        if self._exec(f"{prefix} true", self._sudo_password + "\n").returncode != 0:
            raise RemoteError("sudo password rejected")
        return prefix
