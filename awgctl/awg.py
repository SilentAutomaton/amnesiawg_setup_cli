"""AmneziaWG configuration logic. Pure functions, no I/O and no subprocess."""

from __future__ import annotations

import ipaddress
import random
import re
from dataclasses import dataclass, field

INTERFACE_NAME = "awg0"

# Size of each AmneziaWG packet type before its junk is added. Two types must never
# reach the same total size, or the junk stops hiding which type a packet is.
PACKET_BASE_SIZE = {"S1": 148, "S2": 92, "S3": 64, "S4": 32}

# With HeaderProtectionKey set, amneziawg-go needs every S value to hold its 12 byte nonce.
JUNK_SIZE_MIN = 12
JUNK_SIZE_MAX = {"S1": 150, "S2": 150, "S3": 64, "S4": 32}

# H1..H4 are ranges of message type values. They must not overlap, and 1..4 are plain WireGuard.
MAGIC_HEADER_MIN = 5
MAGIC_HEADER_MAX = 2**31 - 1

# I1 is sent before every handshake. It imitates a packet of a common UDP protocol.
DECOY_DOMAINS = ("yandex.ru", "vk.com", "mail.ru", "ozon.ru", "gosuslugi.ru", "wildberries.ru")

# Interface parameters that both sides of the tunnel must agree on. Client configs
# copy them from the server config so a client can never drift from its server.
SHARED_PARAM_KEYS = (
    "Jc",
    "Jmin",
    "Jmax",
    "S1",
    "S2",
    "S3",
    "S4",
    "H1",
    "H2",
    "H3",
    "H4",
    "I1",
    "I2",
    "I3",
    "I4",
    "I5",
    "HeaderProtectionKey",
    "ContentPaddingAddition",
    "RekeyAfterTime",
    "RekeyTimeout",
    "RejectAfterTime",
    "KeepaliveTimeout",
    "MaxHandshakeAttempts",
    "RandomTrailers",
    "DisableCookies",
)


PEER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def check_peer_name(name: str) -> str:
    """A peer name becomes both a config comment and a local file name."""
    if not PEER_NAME_RE.match(name):
        raise ValueError(f"invalid client name {name!r}: use letters, digits, dot, dash or underscore")
    return name


@dataclass
class Peer:
    name: str = ""
    created: str = ""
    fields: dict[str, str] = field(default_factory=dict)

    @property
    def address(self) -> str:
        return self.fields.get("AllowedIPs", "").split("/")[0]

    @property
    def public_key(self) -> str:
        return self.fields.get("PublicKey", "")


@dataclass
class Conf:
    interface: dict[str, str] = field(default_factory=dict)
    peers: list[Peer] = field(default_factory=list)


def generate_obfuscation(header_protection_key: str, rng: random.Random | None = None) -> dict[str, str]:
    """Randomise the AmneziaWG obfuscation parameters for one server."""
    rng = rng or random.Random()
    while True:
        sizes = {key: rng.randint(JUNK_SIZE_MIN, limit) for key, limit in JUNK_SIZE_MAX.items()}
        if _packet_types_stay_distinct(sizes):
            break

    junk_min = rng.randint(10, 30)
    params = {
        "Jc": str(rng.randint(4, 6)),
        "Jmin": str(junk_min),
        "Jmax": str(junk_min + rng.randint(20, 80)),
        **{key: str(value) for key, value in sizes.items()},
        **_magic_headers(rng),
        "I1": rng.choice(SIGNATURE_PACKETS)(rng),
        "I2": "",
        "I3": "",
        "I4": "",
        "I5": "",
        "HeaderProtectionKey": header_protection_key,
        "ContentPaddingAddition": "10-100",
        "RekeyAfterTime": "100-120",
        "RekeyTimeout": "3-7",
        "RejectAfterTime": "150-180",
        "KeepaliveTimeout": "5-15",
        "MaxHandshakeAttempts": "15-20",
        "RandomTrailers": "on",
        "DisableCookies": "on",
    }
    return params


def _packet_types_stay_distinct(sizes: dict[str, int]) -> bool:
    totals = [PACKET_BASE_SIZE[key] + size for key, size in sizes.items()]
    return len(set(totals)) == len(totals) and len(set(sizes.values())) == len(sizes)


def _magic_headers(rng: random.Random) -> dict[str, str]:
    # Eight sorted distinct bounds paired up give four ranges that cannot overlap.
    bounds = sorted(rng.sample(range(MAGIC_HEADER_MIN, MAGIC_HEADER_MAX + 1), 8))
    ranges = [f"{bounds[i]}-{bounds[i + 1]}" for i in range(0, 8, 2)]
    rng.shuffle(ranges)
    return {f"H{i + 1}": value for i, value in enumerate(ranges)}


def _hex(data: bytes) -> str:
    return f"<b 0x{data.hex()}>"


def _dns_name(domain: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode() for label in domain.split(".")) + b"\0"


def _dns_query(rng: random.Random) -> str:
    question = _dns_name(rng.choice(DECOY_DOMAINS)) + bytes.fromhex("00010001")
    return "<r 2>" + _hex(bytes.fromhex("01000001000000000000") + question)


def _quic_initial(rng: random.Random) -> str:
    # Long header, version 1, 8 byte DCID, no SCID, no token, then 1182 bytes of
    # packet number and payload, so the datagram is the 1200 bytes QUIC requires.
    return _hex(bytes.fromhex("c30000000108")) + "<r 8>" + _hex(bytes.fromhex("0000449e")) + "<r 1182>"


def _sip_register(rng: random.Random) -> str:
    domain = rng.choice(DECOY_DOMAINS)
    return (
        _hex(f"REGISTER sip:{domain} SIP/2.0\r\nVia: SIP/2.0/UDP 192.168.1.".encode())
        + "<rd 2>"
        + _hex(b":5060;branch=z9hG4bK")
        + "<rc 16>"
        + _hex(b"\r\nMax-Forwards: 70\r\nFrom: <sip:")
        + "<rd 6>"
        + _hex(f"@{domain}>;tag=".encode())
        + "<rc 10>"
        + _hex(b"\r\nTo: <sip:")
        + "<rd 6>"
        + _hex(f"@{domain}>\r\nCall-ID: ".encode())
        + "<rc 24>"
        + _hex(b"\r\nCSeq: 1 REGISTER\r\nExpires: 3600\r\nContent-Length: 0\r\n\r\n")
    )


SIGNATURE_PACKETS = (_dns_query, _quic_initial, _sip_register)


_SECTION_RE = re.compile(r"^\[(\w+)\]$")
_PAIR_RE = re.compile(r"^([A-Za-z0-9_]+)\s*=\s*(.*)$")
_META_RE = re.compile(r"^#\s*(name|created)\s*:\s*(.*)$")


def parse_conf(text: str) -> Conf:
    conf = Conf()
    current: dict[str, str] | None = None
    pending: dict[str, str] = {}

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue

        meta = _META_RE.match(line)
        if meta:
            pending[meta.group(1)] = meta.group(2).strip()
            continue
        if line.startswith("#"):
            continue

        section = _SECTION_RE.match(line)
        if section:
            if section.group(1) == "Peer":
                peer = Peer(name=pending.get("name", ""), created=pending.get("created", ""))
                conf.peers.append(peer)
                current = peer.fields
            else:
                current = conf.interface
            pending = {}
            continue

        pair = _PAIR_RE.match(line)
        if pair and current is not None:
            current[pair.group(1)] = pair.group(2).strip()

    return conf


def render_conf(conf: Conf) -> str:
    lines = ["[Interface]"]
    lines += _render_pairs(conf.interface)
    for peer in conf.peers:
        lines.append("")
        if peer.name:
            lines.append(f"# name: {peer.name}")
        if peer.created:
            lines.append(f"# created: {peer.created}")
        lines.append("[Peer]")
        lines += _render_pairs(peer.fields)
    return "\n".join(lines) + "\n"


def _render_pairs(pairs: dict[str, str]) -> list[str]:
    # Every AmneziaWG parameter is optional, so an empty value means "leave it out".
    return [f"{key} = {value}" for key, value in pairs.items() if value != ""]


def server_address(subnet: str) -> str:
    """First host of the subnet, in CIDR form: 10.8.1.0/24 -> 10.8.1.1/24."""
    network = ipaddress.ip_network(subnet, strict=False)
    return f"{next(network.hosts())}/{network.prefixlen}"


def next_client_ip(conf: Conf) -> str:
    network = ipaddress.ip_network(conf.interface["Address"], strict=False)
    used = {ipaddress.ip_interface(conf.interface["Address"]).ip}
    for peer in conf.peers:
        for cidr in peer.fields.get("AllowedIPs", "").split(","):
            if cidr.strip():
                used.add(ipaddress.ip_interface(cidr.strip()).ip)

    for host in network.hosts():
        if host not in used:
            return str(host)
    raise ValueError(f"no free address left in {network}")


def build_server_conf(private_key: str, address: str, listen_port: int, obfuscation: dict[str, str]) -> Conf:
    interface = {
        "PrivateKey": private_key,
        "Address": address,
        "ListenPort": str(listen_port),
        **obfuscation,
    }
    return Conf(interface=interface)


def find_peer(conf: Conf, name: str) -> Peer | None:
    return next((peer for peer in conf.peers if peer.name == name), None)


def add_peer(conf: Conf, name: str, created: str, public_key: str, preshared_key: str, address: str) -> Peer:
    peer = Peer(
        name=name,
        created=created,
        fields={
            "PublicKey": public_key,
            "PresharedKey": preshared_key,
            "AllowedIPs": f"{address}/32",
        },
    )
    conf.peers.append(peer)
    return peer


def remove_peer(conf: Conf, name: str) -> Peer | None:
    peer = find_peer(conf, name)
    if peer is not None:
        conf.peers.remove(peer)
    return peer


def build_client_conf(
    server_conf: Conf,
    *,
    private_key: str,
    address: str,
    dns: list[str],
    mtu: int,
    server_public_key: str,
    preshared_key: str,
    endpoint: str,
    persistent_keepalive: str,
) -> str:
    interface = {
        "PrivateKey": private_key,
        "Address": f"{address}/32",
        "DNS": ", ".join(dns),
        "MTU": str(mtu),
    }
    interface.update({key: server_conf.interface[key] for key in SHARED_PARAM_KEYS if key in server_conf.interface})

    peer = Peer(
        fields={
            "PublicKey": server_public_key,
            "PresharedKey": preshared_key,
            "AllowedIPs": "0.0.0.0/0, ::/0",
            "Endpoint": endpoint,
            "PersistentKeepalive": persistent_keepalive,
        }
    )
    return render_conf(Conf(interface=interface, peers=[peer]))
