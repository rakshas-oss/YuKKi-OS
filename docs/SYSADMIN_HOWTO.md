# YuKKi OS v6.7.0 — Sysadmin How-To

> Research/demo software. Use strict network boundaries and secret handling.

## 1) Build and install

```bash
cd /srv/yukki/YuKKi-OS
cargo build --release --locked
sudo install -d -o root -g root -m 0755 /usr/local/libexec/yukki
sudo install -o root -g root -m 0755 target/release/yukki_core_node /usr/local/libexec/yukki/yukki_core_node
```

## 2) Create service account and env files

```bash
sudo useradd --system --home /var/lib/yukki --shell /usr/sbin/nologin yukki
sudo install -d -o yukki -g yukki -m 0750 /var/lib/yukki
sudo install -d -o root -g yukki -m 0750 /etc/yukki
```

`/etc/yukki/bootstrap.env` example:

```bash
YUKKI_PSK_HEX=<64_hex_characters>
RUST_LOG=info
YUKKI_BROKER_ENDPOINT=127.0.0.1:9000
YUKKI_BROKER_CONNECT_TIMEOUT_MS=3000
YUKKI_BROKER_REQUEST_TIMEOUT_MS=5000
YUKKI_BROKER_MAX_FRAME_BYTES=65536
YUKKI_BROKER_TRANSPORT_SECURITY=authenticated-proxy
```

```bash
sudo chown root:yukki /etc/yukki/bootstrap.env
sudo chmod 0640 /etc/yukki/bootstrap.env
sudo cp /etc/yukki/bootstrap.env /etc/yukki/node.env
sudo chown root:yukki /etc/yukki/node.env
sudo chmod 0640 /etc/yukki/node.env
```

## 3) systemd units

Bootstrap unit (`/etc/systemd/system/yukki-bootstrap.service`):

```ini
[Unit]
Description=YuKKi-OS bootstrap node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=yukki
Group=yukki
WorkingDirectory=/srv/yukki/YuKKi-OS
EnvironmentFile=/etc/yukki/bootstrap.env
ExecStart=/usr/local/libexec/yukki/yukki_core_node bootstrap 10.0.0.10:7660
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/yukki

[Install]
WantedBy=multi-user.target
```

Peer unit (`/etc/systemd/system/yukki-peer.service`):

```ini
[Unit]
Description=YuKKi-OS peer node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=yukki
Group=yukki
WorkingDirectory=/srv/yukki/YuKKi-OS
EnvironmentFile=/etc/yukki/node.env
ExecStart=/usr/local/libexec/yukki/yukki_core_node node 10.0.0.10:7660 10.0.0.21:9999
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/yukki

[Install]
WantedBy=multi-user.target
```

Activate:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now yukki-bootstrap.service
sudo systemctl enable --now yukki-peer.service
```

## 4) Health checks

```bash
systemctl status yukki-bootstrap.service --no-pager
journalctl -u yukki-bootstrap.service -n 100 --no-pager
ss -tlnp | grep 7660
```

## 5) Upgrade and rollback

Upgrade:

```bash
cd /srv/yukki/YuKKi-OS
git pull --ff-only
cargo build --release --locked
sudo cp /usr/local/libexec/yukki/yukki_core_node /usr/local/libexec/yukki/yukki_core_node.prev
sudo install -o root -g root -m 0755 target/release/yukki_core_node /usr/local/libexec/yukki/yukki_core_node
sudo systemctl restart yukki-bootstrap.service yukki-peer.service
```

Rollback:

```bash
sudo cp /usr/local/libexec/yukki/yukki_core_node.prev /usr/local/libexec/yukki/yukki_core_node
sudo systemctl restart yukki-bootstrap.service yukki-peer.service
```

## 6) Broker interoperability caveat

Broker traffic is not end-to-end authenticated by YuKKi-OS. Keep broker endpoint loopback/private or behind authenticated proxy/mTLS.
