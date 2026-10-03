"""Deploy, inspect and remove the AmneziaWG container."""

from __future__ import annotations

import shlex

from . import awg, remote
from .config import Server
from .ssh import RemoteError, Ssh


def deploy(ssh: Ssh, server: Server, force: bool = False) -> None:
    settings = server.awg
    print(f"server: {ssh.run('uname -sr').strip()}")

    existing = remote.container_state(ssh, settings.container_name)
    if existing and not force:
        raise RemoteError(f"container {settings.container_name} already exists ({existing}); use --force to replace it")

    if not remote.has_docker(ssh):
        if not server.install_docker:
            raise RemoteError("docker is missing and install_docker is false")
        print("installing docker")
        remote.install_docker(ssh)

    print(f"pulling {settings.image}")
    remote.create_remote_dir(ssh, settings.remote_dir)
    remote.pull_image(ssh, settings.image)

    private_key, _public_key, header_protection_key = remote.generate_keys(ssh, settings.image)
    conf = awg.build_server_conf(
        private_key,
        awg.server_address(settings.subnet),
        settings.listen_port,
        awg.generate_obfuscation(header_protection_key),
    )
    remote.write_conf(ssh, server, conf)
    ssh.put(remote.entrypoint_script(), server.entrypoint_path, mode="700")

    if existing:
        remote.remove_container(ssh, settings.container_name)
    print(f"starting {settings.container_name}")
    remote.start_container(ssh, server)

    state = remote.container_state(ssh, settings.container_name)
    if not state.startswith("Up"):
        logs = ssh.sudo(f"docker logs {shlex.quote(settings.container_name)}", check=False)
        raise RemoteError(f"container did not start ({state or 'missing'})\n{logs}")

    print(f"listening on {server.endpoint}/udp")
    print(f"next: awgctl add-client <name> --server {server.name}")


def status(ssh: Ssh, server: Server) -> None:
    state = remote.container_state(ssh, server.awg.container_name) or "not created"
    print(f"{server.awg.container_name}: {state}")
    print(f"endpoint: {server.endpoint}/udp")
    output = remote.show(ssh, server).strip()
    if output:
        print()
        print(output)


def rotate(ssh: Ssh, server: Server) -> None:
    conf = remote.read_conf(ssh, server)
    _private_key, _public_key, header_protection_key = remote.generate_keys(ssh, server.awg.image)
    conf.interface.update(awg.generate_obfuscation(header_protection_key))
    remote.write_conf(ssh, server, conf)
    # Obfuscation is a device setting, so the interface has to come up again.
    remote.restart_container(ssh, server.awg.container_name)
    print(f"new obfuscation parameters active on {server.endpoint}/udp")

    names = [peer.name or peer.public_key for peer in conf.peers]
    if names:
        print("existing client configs no longer connect, issue them again with remove-client and add-client:")
        print("  " + ", ".join(names))


def destroy(ssh: Ssh, server: Server, purge: bool = False) -> None:
    remote.remove_container(ssh, server.awg.container_name)
    print(f"removed container {server.awg.container_name}")
    if purge:
        remote.remove_remote_dir(ssh, server.awg.remote_dir)
        print(f"removed {server.awg.remote_dir}")
