import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from awgctl import awg

SAMPLE = """
[Interface]
PrivateKey = SERVERPRIV
Address = 10.8.1.1/24
ListenPort = 51820
Jc = 5

# name: laptop
# created: 2026-08-14
[Peer]
PublicKey = LAPTOPPUB
PresharedKey = LAPTOPPSK
AllowedIPs = 10.8.1.2/32

# name: phone
[Peer]
PublicKey = PHONEPUB
AllowedIPs = 10.8.1.5/32
"""


def test_obfuscation_is_valid():
    rng = random.Random(1)
    for _ in range(2000):
        params = awg.generate_obfuscation("HPKEY", rng)
        sizes = {key: int(params[key]) for key in ("S1", "S2", "S3", "S4")}
        assert sizes["S4"] == awg.TRANSPORT_JUNK_SIZE
        for key, limit in awg.JUNK_SIZE_MAX.items():
            assert awg.JUNK_SIZE_MIN <= sizes[key] <= limit
        assert len(set(sizes.values())) == 4
        totals = {awg.PACKET_BASE_SIZE[key] + size for key, size in sizes.items()}
        assert len(totals) == 4
        assert 4 <= int(params["Jc"]) <= 6
        assert params["HeaderProtectionKey"] == "HPKEY"


def test_parse_and_render_round_trip():
    conf = awg.parse_conf(SAMPLE)
    assert conf.interface["Address"] == "10.8.1.1/24"
    assert [peer.name for peer in conf.peers] == ["laptop", "phone"]
    assert conf.peers[0].created == "2026-08-14"
    assert conf.peers[1].created == ""
    assert conf.peers[0].address == "10.8.1.2"

    again = awg.parse_conf(awg.render_conf(conf))
    assert again.interface == conf.interface
    assert [(p.name, p.created, p.fields) for p in again.peers] == [
        (p.name, p.created, p.fields) for p in conf.peers
    ]


def test_empty_values_are_dropped():
    conf = awg.Conf(interface={"PrivateKey": "K", "Jc": "", "Address": "10.8.1.1/24"})
    assert "Jc" not in awg.render_conf(conf)


def test_next_client_ip_fills_gaps():
    conf = awg.parse_conf(SAMPLE)
    assert awg.next_client_ip(conf) == "10.8.1.3"

    empty = awg.build_server_conf("K", awg.server_address("10.8.1.0/24"), 51820, {})
    assert empty.interface["Address"] == "10.8.1.1/24"
    assert awg.next_client_ip(empty) == "10.8.1.2"


def test_next_client_ip_exhausted():
    conf = awg.build_server_conf("K", awg.server_address("10.9.0.0/30"), 51820, {})
    awg.add_peer(conf, "a", "", "PUB", "PSK", "10.9.0.2")
    try:
        awg.next_client_ip(conf)
    except ValueError:
        pass
    else:
        raise AssertionError("expected exhaustion to raise")


def test_add_and_remove_peer():
    conf = awg.parse_conf(SAMPLE)
    awg.add_peer(conf, "tablet", "2026-08-14", "TABPUB", "TABPSK", "10.8.1.3")
    assert awg.find_peer(conf, "tablet").address == "10.8.1.3"
    assert awg.next_client_ip(conf) == "10.8.1.4"

    assert awg.remove_peer(conf, "laptop").public_key == "LAPTOPPUB"
    assert awg.find_peer(conf, "laptop") is None
    assert awg.remove_peer(conf, "laptop") is None
    assert [peer.name for peer in conf.peers] == ["phone", "tablet"]


def test_client_conf_copies_shared_params():
    server = awg.build_server_conf("SPRIV", "10.8.1.1/24", 51820, awg.generate_obfuscation("HPKEY"))
    text = awg.build_client_conf(
        server,
        private_key="CPRIV",
        address="10.8.1.2",
        dns=["1.1.1.1", "1.0.0.1"],
        mtu=1376,
        server_public_key="SPUB",
        preshared_key="PSK",
        endpoint="vpn.example.org:51820",
        persistent_keepalive="25-35",
    )
    client = awg.parse_conf(text)
    assert "SPRIV" not in text
    assert client.interface["Address"] == "10.8.1.2/32"
    assert client.interface["DNS"] == "1.1.1.1, 1.0.0.1"
    for key in awg.SHARED_PARAM_KEYS:
        assert client.interface[key] == server.interface[key]
    assert client.peers[0].fields["Endpoint"] == "vpn.example.org:51820"


if __name__ == "__main__":
    for name, case in sorted(globals().items()):
        if name.startswith("test_"):
            case()
            print(f"ok {name}")
