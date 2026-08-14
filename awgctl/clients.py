"""Issue, list and revoke client configs."""

from __future__ import annotations

import os
from datetime import date
from pathlib import Path

from . import awg, qr, remote
from .config import Server
from .ssh import RemoteError, Ssh


def add_client(ssh: Ssh, server: Server, name: str, out_dir: Path, show_qr: bool = True) -> Path:
    awg.check_peer_name(name)
    settings = server.awg

    conf = remote.read_conf(ssh, server)
    if awg.find_peer(conf, name) is not None:
        raise RemoteError(f"client {name!r} already exists")

    address = awg.next_client_ip(conf)
    private_key, public_key, preshared_key = remote.generate_keys(ssh, settings.image)
    awg.add_peer(conf, name, date.today().isoformat(), public_key, preshared_key, address)
    remote.write_conf(ssh, server, conf)
    remote.apply_config(ssh, server)

    text = awg.build_client_conf(
        conf,
        private_key=private_key,
        address=address,
        dns=settings.dns,
        mtu=settings.mtu,
        server_public_key=remote.public_key(ssh, settings.image, conf.interface["PrivateKey"]),
        preshared_key=preshared_key,
        endpoint=server.endpoint,
        persistent_keepalive=settings.persistent_keepalive,
    )

    path = out_dir / server.name / f"{name}.conf"
    _write_private(path, text)
    print(f"{name} -> {address}, written to {path}")
    if show_qr:
        qr.print_qr(text)
    return path


def remove_client(ssh: Ssh, server: Server, name: str) -> None:
    conf = remote.read_conf(ssh, server)
    if awg.remove_peer(conf, name) is None:
        raise RemoteError(f"no client named {name!r}")
    remote.write_conf(ssh, server, conf)
    remote.apply_config(ssh, server)
    print(f"revoked {name}")


def list_clients(ssh: Ssh, server: Server) -> None:
    conf = remote.read_conf(ssh, server)
    if not conf.peers:
        print("no clients")
        return

    stats = _peer_stats(remote.show(ssh, server))
    rows = [("NAME", "ADDRESS", "CREATED", "LAST HANDSHAKE", "TRANSFER")]
    for peer in conf.peers:
        peer_stats = stats.get(peer.public_key, {})
        rows.append(
            (
                peer.name or "-",
                peer.address,
                peer.created or "-",
                peer_stats.get("latest handshake", "never"),
                peer_stats.get("transfer", "-"),
            )
        )

    widths = [max(len(row[column]) for row in rows) for column in range(len(rows[0]))]
    for row in rows:
        print("  ".join(value.ljust(width) for value, width in zip(row, widths)).rstrip())


def _peer_stats(show_output: str) -> dict[str, dict[str, str]]:
    stats: dict[str, dict[str, str]] = {}
    current: dict[str, str] | None = None
    for line in show_output.splitlines():
        key, _, value = line.strip().partition(":")
        if key == "peer":
            current = stats.setdefault(value.strip(), {})
        elif current is not None and key in ("latest handshake", "transfer"):
            current[key] = value.strip()
    return stats


def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(text)
