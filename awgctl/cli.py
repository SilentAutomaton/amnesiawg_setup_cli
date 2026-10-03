"""Command line entry point: argument parsing and dispatch only."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import clients, config, deploy
from .ssh import RemoteError, Ssh

DEFAULT_OUT_DIR = Path("clients")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="awgctl", description="Deploy AmneziaWG on a remote VPS over SSH")
    parser.add_argument("--config", help="path to the config file")
    parser.add_argument("--server", help="server name from the config")
    parser.add_argument("-v", "--verbose", action="store_true", help="echo every remote command")

    commands = parser.add_subparsers(dest="command", required=True)

    deploy_command = commands.add_parser("deploy", help="pull the image, write the config and start the container")
    deploy_command.add_argument("--force", action="store_true", help="replace an existing container")

    commands.add_parser("status", help="container state and interface statistics")

    destroy_command = commands.add_parser("destroy", help="remove the container")
    destroy_command.add_argument("--purge", action="store_true", help="also delete the remote directory")
    destroy_command.add_argument("--yes", action="store_true", help="do not ask for confirmation")

    rotate_command = commands.add_parser("rotate", help="generate new obfuscation parameters on a deployed server")
    rotate_command.add_argument("--yes", action="store_true", help="do not ask for confirmation")

    add_command = commands.add_parser("add-client", help="create a client and write its config")
    add_command.add_argument("name")
    add_command.add_argument("--out", type=Path, default=DEFAULT_OUT_DIR, help="output directory for client configs")
    add_command.add_argument("--no-qr", action="store_true", help="do not print a QR code")

    commands.add_parser("list-clients", help="list clients with their last handshake")

    remove_command = commands.add_parser("remove-client", help="revoke a client")
    remove_command.add_argument("name")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        server = config.load(args.config, args.server)
        with Ssh(server, verbose=args.verbose) as ssh:
            ssh.connect()
            _dispatch(args, ssh, server)
    except (config.ConfigError, RemoteError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    return 0


def _dispatch(args: argparse.Namespace, ssh: Ssh, server: config.Server) -> None:
    if args.command == "deploy":
        deploy.deploy(ssh, server, force=args.force)
    elif args.command == "status":
        deploy.status(ssh, server)
    elif args.command == "destroy":
        if args.yes or _confirm(f"remove container {server.awg.container_name} on {server.host}?"):
            deploy.destroy(ssh, server, purge=args.purge)
    elif args.command == "rotate":
        if args.yes or _confirm(f"replace obfuscation on {server.host}? every client config must be issued again"):
            deploy.rotate(ssh, server)
    elif args.command == "add-client":
        clients.add_client(ssh, server, args.name, args.out, show_qr=not args.no_qr)
    elif args.command == "list-clients":
        clients.list_clients(ssh, server)
    elif args.command == "remove-client":
        clients.remove_client(ssh, server, args.name)


def _confirm(question: str) -> bool:
    return input(f"{question} [y/N] ").strip().lower() in ("y", "yes")
