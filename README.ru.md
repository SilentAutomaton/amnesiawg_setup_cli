[English version](README.md)

# awgctl

Ставит сервер [AmneziaWG](https://github.com/amnezia-vpn/amneziawg-go) в
Docker-контейнер на удалённом VPS по SSH и выдаёт для него клиентские конфиги.

- Работает без root по SSH: пользователь в группе `docker` или пользователь с
  sudo и паролем.
- Работает с SSH-ключом под парольной фразой, через `ssh-agent` или обычный
  запрос `ssh`.
- Python 3.11 или новее, только стандартная библиотека. Необязательный пакет `segno`
  рисует QR-коды в терминале.
- На сервере ничего не собирается: образ скачивается из upstream, конфиг
  монтируется в контейнер.

Как это устроено и почему именно так, написано в [docs/DESIGN.md](docs/DESIGN.md)
(на английском).

## Установка

```sh
pip install -e .          # или pip install -e '.[qr]' для QR-кодов
```

## Настройка

```sh
cp config.example.toml config.toml
$EDITOR config.toml
```

`config.toml` в `.gitignore`. Все адреса, порты, подсети и имена образов
задаются там.

## Команды

```sh
awgctl deploy                    # скачать образ, настроить и запустить контейнер
awgctl status                    # состояние контейнера и вывод awg show
awgctl add-client laptop         # пишет clients/<server>/laptop.conf и печатает QR
awgctl list-clients              # имена, адреса, последнее рукопожатие, трафик
awgctl remove-client laptop      # отозвать клиента без перезапуска контейнера
awgctl rotate                    # новые параметры обфускации, всем клиентам нужны новые конфиги
awgctl destroy --purge           # удалить контейнер и каталог на сервере
```

Любая команда понимает `--server NAME`, чтобы выбрать сервер из конфига,
`--config PATH` для другого файла конфига и `-v`, чтобы видеть каждую команду,
которая выполняется на сервере.

`add-client` и `remove-client` применяют изменения к работающему интерфейсу
через `awg syncconf`, и сессии остальных клиентов не рвутся.

## Что нужно на VPS

- Linux с systemd. Если Docker должен поставить `awgctl`, нужен один из
  `apt-get`, `dnf`, `yum`, `zypper` или `pacman`. Когда Docker уже стоит,
  укажите `install_docker = false`.
- SSH-пользователь должен иметь доступ к демону Docker: быть в группе `docker`
  (`privilege = "none"`) или уметь запускать `sudo` (при `privilege = "auto"`
  пароль спросят, когда он понадобится).
- UDP-порт из `listen_port` должен быть открыт в межсетевом экране провайдера.

## Тесты

```sh
python tests/test_awg.py
```

## Лицензия

MIT
