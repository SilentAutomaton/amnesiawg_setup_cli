# awgctl

Deploy an [AmneziaWG](https://github.com/amnezia-vpn/amneziawg-go) server into a Docker container on
a remote VPS over SSH, and issue client configs for it.

- Works with a non-root SSH user: a member of the `docker` group, or a sudo user with a password.
- Works with a passphrase-protected SSH key, through `ssh-agent` or the normal `ssh` prompt.
- Python 3.11+, standard library only. The optional `segno` package adds terminal QR codes.
- No build on the server: the upstream image is pulled and the config is bind-mounted.

See [docs/DESIGN.md](docs/DESIGN.md) for how it works and why.

## Install

```sh
pip install -e .          # or: pip install -e '.[qr]' for QR codes
```

## Configure

```sh
cp config.example.toml config.toml
$EDITOR config.toml
```

`config.toml` is git-ignored. Every address, port, subnet and image name lives there.

## Use

```sh
awgctl deploy                    # pull, configure and start the container
awgctl status                    # container state and awg show
awgctl add-client laptop         # writes clients/<server>/laptop.conf and prints a QR
awgctl list-clients              # names, addresses, last handshake, transfer
awgctl remove-client laptop      # revoke without restarting the container
awgctl destroy --purge           # remove the container and the remote directory
```

Every command takes `--server NAME` to pick a server from the config, `--config PATH` to point at a
different config file, and `--dry-run` to print the remote commands instead of running them.

## Requirements on the VPS

- Linux with systemd, and one of `apt-get`, `dnf`, `yum`, `zypper` or `pacman` if you want `awgctl`
  to install Docker for you. Set `install_docker = false` when Docker is already there.
- The SSH user must be able to reach the Docker daemon: either in the `docker` group
  (`privilege = "none"`), or able to run `sudo` (`privilege = "auto"` will ask for the password when
  it is needed).
- The UDP port from `listen_port` must be open in the provider firewall.
