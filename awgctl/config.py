"""Configuration: every default in one place, a TOML file layered on top."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

CONFIG_SEARCH_PATHS = (
    Path("config.toml"),
    Path.home() / ".config" / "awgctl" / "config.toml",
)

DEFAULTS = {
    "port": 22,
    "user": "",
    "identity_file": "",
    "privilege": "auto",
    "install_docker": True,
    "awg": {
        "listen_port": 51820,
        "subnet": "10.8.1.0/24",
        "endpoint": "",
        "dns": ["1.1.1.1", "1.0.0.1"],
        "mtu": 1376,
        "persistent_keepalive": "25-35",
        "image": "amneziavpn/amneziawg-go:latest",
        "container_name": "awgctl",
        "remote_dir": "/opt/awgctl",
        "docker_run_extra": [],
    },
}

PRIVILEGE_MODES = ("auto", "none", "sudo", "root")


class ConfigError(Exception):
    pass


@dataclass
class Awg:
    listen_port: int
    subnet: str
    endpoint: str
    dns: list[str]
    mtu: int
    persistent_keepalive: str
    image: str
    container_name: str
    remote_dir: str
    docker_run_extra: list[str]


@dataclass
class Server:
    name: str
    host: str
    port: int
    user: str
    identity_file: str
    privilege: str
    install_docker: bool
    awg: Awg

    @property
    def endpoint(self) -> str:
        return self.awg.endpoint or f"{self.host}:{self.awg.listen_port}"

    @property
    def conf_path(self) -> str:
        return f"{self.awg.remote_dir}/awg0.conf"

    @property
    def entrypoint_path(self) -> str:
        return f"{self.awg.remote_dir}/entrypoint.sh"


def load(path: str | None = None, name: str | None = None) -> Server:
    config_path = _resolve_path(path)
    with config_path.open("rb") as handle:
        document = tomllib.load(handle)

    servers = document.get("server", {})
    if not servers:
        raise ConfigError(f"{config_path} defines no [server.<name>] section")

    name = name or document.get("default_server") or next(iter(servers))
    if name not in servers:
        raise ConfigError(f"unknown server {name!r}, config has: {', '.join(servers)}")

    return _build(name, servers[name])


def _resolve_path(path: str | None) -> Path:
    if path:
        candidate = Path(path).expanduser()
        if not candidate.is_file():
            raise ConfigError(f"config file not found: {candidate}")
        return candidate

    for candidate in CONFIG_SEARCH_PATHS:
        if candidate.is_file():
            return candidate
    searched = ", ".join(str(candidate) for candidate in CONFIG_SEARCH_PATHS)
    raise ConfigError(f"no config file found, looked in: {searched}. Copy config.example.toml first.")


def _build(name: str, section: dict) -> Server:
    _reject_unknown_keys(f"server.{name}", section, set(DEFAULTS) | {"host"})
    awg_section = section.get("awg", {})
    _reject_unknown_keys(f"server.{name}.awg", awg_section, set(DEFAULTS["awg"]))

    if "host" not in section:
        raise ConfigError(f"server.{name} has no host")

    privilege = section.get("privilege", DEFAULTS["privilege"])
    if privilege not in PRIVILEGE_MODES:
        raise ConfigError(f"server.{name}.privilege must be one of: {', '.join(PRIVILEGE_MODES)}")

    awg = Awg(**{key: awg_section.get(key, value) for key, value in DEFAULTS["awg"].items()})
    return Server(
        name=name,
        host=section["host"],
        port=section.get("port", DEFAULTS["port"]),
        user=section.get("user", DEFAULTS["user"]),
        identity_file=section.get("identity_file", DEFAULTS["identity_file"]),
        privilege=privilege,
        install_docker=section.get("install_docker", DEFAULTS["install_docker"]),
        awg=awg,
    )


def _reject_unknown_keys(where: str, section: dict, allowed: set[str]) -> None:
    unknown = sorted(set(section) - allowed)
    if unknown:
        raise ConfigError(f"unknown keys in [{where}]: {', '.join(unknown)}")
