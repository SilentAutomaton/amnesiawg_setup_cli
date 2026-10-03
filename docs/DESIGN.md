# awgctl — design

## Goal

One CLI that does what the AmneziaVPN desktop client does for the AmneziaWG protocol only:

1. Deploy an AmneziaWG server into a Docker container on a remote VPS over SSH, from scratch.
2. Issue, list and revoke client configs for an already deployed server.

Constraints that drove the design:

- Must work when the SSH user is **not root**: either a member of the `docker` group, or a sudo user
  who has to type a password.
- Must work with an **SSH key that has a passphrase**.
- Readable and easy to edit by both people and agents. Few files, thin layers, no speculative
  abstractions.
- No literal addresses, ports, subnets or image names in code. Everything lives in config.

## Reconnaissance: how AmneziaVPN does it

Source: `github.com/amnezia-vpn/amnezia-client`, plus `amneziawg-go` and `amneziawg-tools`.

### Install flow

`client/core/controllers/selfhosted/installController.cpp` runs, over one libssh session:

| Step | Script |
|---|---|
| create work dir, create the `amnezia-dns-net` bridge | `server_scripts/prepare_host.sh` |
| install Docker with the distro package manager | `server_scripts/install_docker.sh` |
| upload `Dockerfile`, then build | `server_scripts/build_container.sh` |
| start the container | `server_scripts/awg/run_container.sh` |
| generate keys and write `awg0.conf` **inside** the container | `server_scripts/awg/configure_container.sh` |
| upload `start.sh` into the container and exec it | `server_scripts/awg/start.sh` |

Scripts are Qt resources with `$VARIABLE` placeholders substituted by
`core/utils/selfhosted/scriptsRegistry.cpp` before being sent line by line over SSH.

### Server side

`configure_container.sh` runs `awg genkey`, `awg pubkey`, `awg genpsk` inside the container, writes
`/opt/amnezia/awg/awg0.conf`, and then deletes every line whose value came out empty — all AWG
parameters are optional.

`start.sh` runs `awg-quick down` (to survive a restart), `awg-quick up`, adds iptables `ACCEPT` rules
for the tunnel interface and `MASQUERADE` for the tunnel subnet, then blocks on `tail -f /dev/null`.

`run_container.sh` uses `--privileged --cap-add=NET_ADMIN --cap-add=SYS_MODULE`,
`-v /lib/modules:/lib/modules` and `--sysctl net.ipv4.conf.all.src_valid_mark=1`.

### Adding a peer

`core/configurators/wireguardConfigurator.cpp`:

1. `cat awg0.conf | grep AllowedIPs` to find allocated addresses.
2. Take the last one and add 1; `.254` jumps by 3 and `.255` by 2 to skip network and broadcast.
3. Generate an X25519 keypair (client-side, via OpenSSL).
4. Append a `[Peer]` block to `awg0.conf`.
5. Apply live with `awg syncconf awg0 <(awg-quick strip awg0.conf)` — existing sessions survive.

Peer names are kept in a separate `clientsTable` JSON file inside the container
(`core/controllers/selfhosted/usersController.cpp`).

### Obfuscation parameters

`core/installers/awgInstaller.cpp` (protocol 3.1) writes:

- `Jc` in 4..6, `Jmin` 10, `Jmax` 50.
- `S1`..`S4` = 12. With `HeaderProtectionKey` set, amneziawg-go requires every `S` to be at least
  12, the header cipher nonce size.
- `H1..H4` = 1, 2, 3, 4.
- `HeaderProtectionKey` is a fresh X25519 private key.
- `I1` is a fixed DNS-like signature packet, sent before every handshake. `I2`..`I5` are empty.

These values are the same on every Amnezia server, which makes them a fingerprint. awgctl keeps the
3.1 parameters and randomises the rest per server, within what amneziawg-go accepts:

- `Jmin` in 10..30, `Jmax` = `Jmin` + 20..80.
- `S1` in 12..150, `S2` in 12..150, `S3` in 12..64, `S4` in 12..32. `S1 + MessageInitiationSize`,
  `S2 + MessageResponseSize`, `S3 + MessageCookieReplySize` and `S4 + MessageTransportHeaderSize`
  must all differ, and the four `S` values must be distinct. Otherwise two packet types end up the
  same size on the wire.
- `H1..H4` are four ranges `lo-hi` in 5..2^31-1 that do not overlap (amneziawg-go rejects overlap).
  Each range is at most 20000 wide: with `RandomTrailers = on`, amneziawg-go drops a transport
  packet whose header falls into H1..H3 (amneziawg-go issue #186), and wide ranges caused about
  12 % loss.
- `I1` imitates one of: a DNS query for a popular domain, a QUIC v1 Initial packet (1200 bytes), or
  a SIP REGISTER. The fixed parts are `<b 0x..>` tags, the variable parts are `<r>`, `<rc>`, `<rd>`
  tags, so every handshake sends a different packet.

`awgctl rotate` writes a new set into the server config and restarts the container. Client configs
carry the same parameters, so every client must be issued again afterwards.

### Base image

`amneziavpn/amneziawg-go:latest` is Alpine plus `awg`, `awg-quick`, `amneziawg-go`, `iproute2`,
`iptables` and `bash`. It declares **no ENTRYPOINT and no CMD**, so the command must be supplied at
`docker run`. `awg-quick` tries `ip link add ... type amneziawg` first and falls back to the
`amneziawg-go` userspace driver when the kernel module is absent, so no kernel module is required.

### Limitation we fix

Amnezia calls `sudo` bare and authenticates only through libssh. In practice it needs root or
passwordless sudo, and it cannot use an SSH agent or `~/.ssh/config`.

## Our design

### Transport: the system `ssh` binary

`awgctl/ssh.py` shells out to `ssh` with a per-run `ControlMaster` socket. One authentication for the
whole run, so a passphrase-protected key is unlocked once — by `ssh-agent` or by the `ssh` binary's
own prompt. `~/.ssh/config`, `ProxyJump`, `known_hosts` and hardware keys keep working for free.
This is why we do not use paramiko.

Privilege handling (`Ssh.sudo`):

| mode | behaviour |
|---|---|
| `none`, `root` | no prefix |
| `sudo` | `sudo -n` if it works, else `sudo -S -p ''` with the password on stdin |
| `auto` | probe once: plain `docker info` → `none`; `sudo -n true` → passwordless sudo; else prompt |

The sudo password is read with `getpass`, held in memory only, never written to disk, never placed in
argv and never logged.

File transfer is `ssh host 'cat > path'` on stdin and `ssh host 'cat path'`. No scp, no sftp, no
temporary files left on the server.

### No build on the VPS

We `docker pull` the upstream image and bind-mount a host directory into it. There is no `Dockerfile`
and no `docker build` step, so deploy is a pull plus a run. Everything the server needs is in one
directory, `remote_dir`:

```
<remote_dir>/awg0.conf      server config with all peers, mode 600
<remote_dir>/entrypoint.sh  container startup script
```

The container runs with `--cap-add NET_ADMIN --device /dev/net/tun` instead of `--privileged`, plus
`--sysctl net.ipv4.conf.all.src_valid_mark=1` and `--sysctl net.ipv4.ip_forward=1`. `docker_run_extra`
in the config exists so an awkward kernel can be handled without touching code.

`entrypoint.sh` detects the outbound interface with `ip route show default` instead of assuming
`eth0`/`eth1`.

### Keys are generated on the server

`docker run --rm <image> sh -c 'awg genkey'` and friends. The tool therefore needs no local crypto
library at all — Python's standard library has no X25519.

Verified locally against the real image: the container starts with this narrow capability set, the
userspace driver comes up, `awg` accepts every 3.1 parameter we write, the MASQUERADE rule lands,
and `awg syncconf` applies a new peer to the live interface.

### The server is the only source of truth

There is no local state file. `awg0.conf` on the server holds the interface settings, the
obfuscation parameters and every peer. Peer names live in it as comments:

```
# name: laptop
# created: 2026-08-14
[Peer]
PublicKey = ...
```

`awg-quick strip` already discards comments before the config reaches `awg syncconf`, so one file is
both the runtime config and the client registry. This is simpler than Amnezia's separate
`clientsTable` and cannot drift out of sync with it.

Client configs are rendered from the parameters read back off the server, so a client always matches
the server it was issued from. There is one renderer for both sides: `render_conf` writes the server
config, the client config and every rewrite, so there is no template that can drift from the parser.

Each peer gets its own preshared key. Amnezia shares one key across every client; per-peer keys cost
nothing here because the key is generated together with the peer's keypair in the same round trip.

`I1`..`I5` are written as normal keys in the server config. Upstream keeps them as comments there,
but the image's `awg` accepts them, so the parser needs no special case. Only the side that starts a
handshake sends them.

### Module map

| file | responsibility |
|---|---|
| `awgctl/awg.py` | pure functions: obfuscation parameters, IP allocation, config parse and render, peer add and remove. The only module worth testing. |
| `awgctl/config.py` | defaults plus TOML overrides, resolved into a `Server` dataclass |
| `awgctl/ssh.py` | `Ssh`: `run`, `sudo`, `put`, `get` |
| `awgctl/remote.py` | Docker and host operations expressed through `Ssh` |
| `awgctl/deploy.py` | `deploy`, `status`, `rotate`, `destroy` |
| `awgctl/clients.py` | `add-client`, `list-clients`, `remove-client` |
| `awgctl/qr.py` | terminal QR, optional `segno` dependency |
| `awgctl/cli.py` | argparse and dispatch, no logic |
| `awgctl/assets/entrypoint.sh` | the only asset; everything else is rendered |

There is no `--dry-run`. A dry run cannot produce a config, because the keys come from the server, so
it would have to lie about what it did. `-v/--verbose` echoes every remote command instead, which
gives the same review value truthfully.

Pure logic sits in `awg.py`; the other modules stay thin and side-effecting. No class hierarchy, no
plugin registry, no interface with a single implementation.

### Testing

`tests/test_awg.py` is plain `assert` statements, no framework. It covers the obfuscation constraint
solver, the `I1` tag syntax, IP allocation including the `.254` and exhaustion edges, config parse/render round-trip, and
peer add/remove.
