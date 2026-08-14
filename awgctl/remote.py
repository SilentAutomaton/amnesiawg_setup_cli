"""Docker and host operations on the server, expressed through Ssh."""

from __future__ import annotations

import shlex
from importlib.resources import files

from . import awg
from .config import Server
from .ssh import RemoteError, Ssh

CONTAINER_CONF_DIR = "/etc/awg"
CONTAINER_CONF = f"{CONTAINER_CONF_DIR}/awg0.conf"

INSTALL_DOCKER = """
if command -v docker >/dev/null 2>&1; then exit 0; fi
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get -qq update && apt-get -yq install docker.io
elif command -v dnf >/dev/null 2>&1; then dnf -yq install docker
elif command -v yum >/dev/null 2>&1; then yum -y -q install docker
elif command -v zypper >/dev/null 2>&1; then zypper -nq install docker
elif command -v pacman >/dev/null 2>&1; then pacman -S --noconfirm --quiet docker
else echo "no supported package manager found" >&2; exit 1
fi
systemctl enable --now docker
"""

# One round trip returns a keypair and a preshared key. Generating them in the
# image means the tool needs no local crypto library.
GEN_KEYS = 'priv=$(awg genkey); printf "%s\\n%s\\n%s\\n" "$priv" "$(printf %s "$priv" | awg pubkey)" "$(awg genpsk)"'


def entrypoint_script() -> str:
    return (files("awgctl.assets") / "entrypoint.sh").read_text()


def install_docker(ssh: Ssh) -> None:
    ssh.sudo(INSTALL_DOCKER)


def has_docker(ssh: Ssh) -> bool:
    return ssh.ok("command -v docker")


def pull_image(ssh: Ssh, image: str) -> None:
    ssh.sudo(f"docker pull {shlex.quote(image)}")


def create_remote_dir(ssh: Ssh, path: str) -> None:
    quoted = shlex.quote(path)
    if ssh.ok(f"mkdir -p {quoted} && chmod 700 {quoted}"):
        return
    # A privileged location needs sudo, then hand it to the login user so that later
    # config writes need no privileges at all.
    owner = ssh.run("id -un").strip()
    ssh.sudo(f"mkdir -p {quoted} && chown {shlex.quote(owner)} {quoted} && chmod 700 {quoted}")


def remove_remote_dir(ssh: Ssh, path: str) -> None:
    ssh.sudo(f"rm -rf {shlex.quote(path)}")


def generate_keys(ssh: Ssh, image: str) -> tuple[str, str, str]:
    """Return (private key, public key, preshared key)."""
    output = ssh.sudo(f"docker run --rm {shlex.quote(image)} sh -c {shlex.quote(GEN_KEYS)}")
    lines = output.split()
    if len(lines) != 3:
        raise RemoteError(f"unexpected key generator output: {output!r}")
    return lines[0], lines[1], lines[2]


def public_key(ssh: Ssh, image: str, private_key: str) -> str:
    command = f"docker run --rm -i {shlex.quote(image)} awg pubkey"
    return ssh.sudo(command, stdin=private_key + "\n").strip()


def container_state(ssh: Ssh, name: str) -> str:
    """Docker status line, or an empty string when the container does not exist."""
    filter_expr = shlex.quote(f"name=^{name}$")
    return ssh.sudo(f"docker ps -a --filter {filter_expr} --format '{{{{.Status}}}}'").strip()


def start_container(ssh: Ssh, server: Server) -> None:
    settings = server.awg
    args = [
        "docker",
        "run",
        "-d",
        "--name",
        settings.container_name,
        "--restart",
        "unless-stopped",
        "--cap-add",
        "NET_ADMIN",
        "--device",
        "/dev/net/tun",
        "--sysctl",
        "net.ipv4.conf.all.src_valid_mark=1",
        "--sysctl",
        "net.ipv4.ip_forward=1",
        "-p",
        f"{settings.listen_port}:{settings.listen_port}/udp",
        "-e",
        f"AWG_SUBNET={settings.subnet}",
        "-v",
        f"{settings.remote_dir}:{CONTAINER_CONF_DIR}:ro",
        *settings.docker_run_extra,
        settings.image,
        "bash",
        f"{CONTAINER_CONF_DIR}/entrypoint.sh",
    ]
    ssh.sudo(shlex.join(args))


def remove_container(ssh: Ssh, name: str) -> None:
    ssh.sudo(f"docker rm -f {shlex.quote(name)}", check=False)


def apply_config(ssh: Ssh, server: Server) -> None:
    """Load the config into the running interface without dropping live sessions."""
    stripped = "/tmp/awg0.strip"
    script = (
        f"awg-quick strip {CONTAINER_CONF} > {stripped} && "
        f"awg syncconf {awg.INTERFACE_NAME} {stripped}; "
        f"status=$?; rm -f {stripped}; exit $status"
    )
    ssh.sudo(f"docker exec {shlex.quote(server.awg.container_name)} sh -c {shlex.quote(script)}")


def show(ssh: Ssh, server: Server) -> str:
    command = f"docker exec {shlex.quote(server.awg.container_name)} awg show {awg.INTERFACE_NAME}"
    return ssh.sudo(command, check=False)


def read_conf(ssh: Ssh, server: Server) -> awg.Conf:
    if not ssh.exists(server.conf_path):
        raise RemoteError(f"{server.conf_path} not found, deploy the server first")
    return awg.parse_conf(ssh.get(server.conf_path))


def write_conf(ssh: Ssh, server: Server, conf: awg.Conf) -> None:
    ssh.put(awg.render_conf(conf), server.conf_path)
