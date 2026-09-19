# YuKKi OS v6.6.6 — Sysadmin How-To

> **Research/demo software. Not production-ready.** The PSK-authenticated mesh is a hardening baseline, not a managed identity system, and the broker hop is not end-to-end authenticated by YuKKi-OS today.

---

## Scope

Use this guide when operating YuKKi-OS as the authenticated control-plane peer
mesh and integrating it with
[`rakshas-oss/overhauled`](https://github.com/rakshas-oss/overhauled) as the
separate GPU placement/execution broker.

Illustrative values below use:

- repo checkout: `/srv/yukki/YuKKi-OS`
- service account: `yukki`
- bootstrap bind: `10.0.0.10:7660`
- peer advertised address: `10.0.0.21:9999`
- broker endpoint: `127.0.0.1:9000`

Adjust paths and addresses for your environment.

---

## Prerequisites

- Linux host with `systemd`-style service management if you want the unit file
  examples below
- Rust stable toolchain
- C99 compiler (`gcc` or `clang`)
- `cargo`
- `openssl` for PSK generation
- Network reachability between peers and whichever authenticated boundary fronts
  the broker hop

Install the toolchain with the commands already used by this repository:

```bash
rustup toolchain install stable
```

---

## Build and install

Build from the repository root:

```bash
cd /srv/yukki/YuKKi-OS
cargo build --release
```

Optional static build:

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

Install the built binary somewhere stable for service management:

```bash
sudo install -d -o root -g root -m 0755 /usr/local/libexec/yukki
sudo install -o root -g root -m 0755 \
  /srv/yukki/YuKKi-OS/target/release/yukki_core_node \
  /usr/local/libexec/yukki/yukki_core_node
```

---

## Service account and filesystem layout

Create a locked-down service account and config directories:

```bash
sudo useradd --system --home /var/lib/yukki --shell /usr/sbin/nologin yukki
sudo install -d -o yukki -g yukki -m 0750 /var/lib/yukki
sudo install -d -o root -g yukki -m 0750 /etc/yukki
sudo install -d -o root -g root -m 0755 /var/log/yukki
```

Suggested layout:

```text
/usr/local/libexec/yukki/yukki_core_node   installed binary
/etc/yukki/bootstrap.env                   bootstrap environment
/etc/yukki/node.env                        peer environment
/var/lib/yukki/                            service home / runtime state
/var/log/yukki/                            optional journal export target
```

YuKKi-OS itself does not create persistent state files today; the important
artifacts to protect are your environment files, service definitions, and the
exact binary you deployed.

---

## Secret generation and permissions

Every bootstrap and peer must share the same 32-byte PSK through
`YUKKI_PSK_HEX`.

Generate one:

```bash
umask 077
openssl rand -hex 32
```

Store it in an environment file readable by `root` and the `yukki` group only:

```bash
sudo tee /etc/yukki/bootstrap.env >/dev/null <<'EOF'
YUKKI_PSK_HEX=replace_with_64_hex_characters
RUST_LOG=info
YUKKI_BROKER_ENDPOINT=127.0.0.1:9000
YUKKI_BROKER_CONNECT_TIMEOUT_MS=3000
YUKKI_BROKER_REQUEST_TIMEOUT_MS=5000
YUKKI_BROKER_MAX_FRAME_BYTES=65536
YUKKI_BROKER_TRANSPORT_SECURITY=authenticated-proxy
EOF
sudo chown root:yukki /etc/yukki/bootstrap.env
sudo chmod 0640 /etc/yukki/bootstrap.env
sudo cp /etc/yukki/bootstrap.env /etc/yukki/node.env
sudo chown root:yukki /etc/yukki/node.env
sudo chmod 0640 /etc/yukki/node.env
```

Operational notes:

- Keep the PSK out of shell history, tickets, and logs.
- Rotate it by replacing the env file on every node, then restarting bootstrap
  and peers in a controlled window.
- `YUKKI_BROKER_TRANSPORT_SECURITY` only records your intended boundary. It does
  not add TLS.

---

## Firewall and network exposure

Expose only what the current implementation requires:

- bootstrap listener TCP port (example: `7660`) to allowed peers
- peer advertised addresses only if other systems must reach them directly
- broker listener only on loopback **or** behind an authenticated proxy/mTLS
  sidecar/service mesh

Current limitations to preserve in your threat model:

- the mesh is PSK-authenticated, not identity-rich
- the broker hop is raw TCP + framed JSON
- YuKKi-OS does not provide end-to-end broker authentication

On a host using `ufw`, an example bootstrap policy would be:

```bash
sudo ufw allow from 10.0.0.0/24 to any port 7660 proto tcp
sudo ufw deny 9000/tcp
```

If `overhauled` listens remotely, deny direct exposure and publish only the
authenticated proxy/service-mesh endpoint instead.

---

## Bootstrap and peer operation

Start a bootstrap node:

```bash
cd /srv/yukki/YuKKi-OS
set -a
. /etc/yukki/bootstrap.env
set +a
/usr/local/libexec/yukki/yukki_core_node bootstrap 10.0.0.10:7660
```

Start a peer node:

```bash
cd /srv/yukki/YuKKi-OS
set -a
. /etc/yukki/node.env
set +a
/usr/local/libexec/yukki/yukki_core_node node 10.0.0.10:7660 10.0.0.21:9999
```

What to expect:

- bootstrap logs `bootstrap listening`
- peer logs `node registered; press Ctrl-C to stop`
- both emit JSON logs to stdout/stderr via `tracing_subscriber`

---

## Broker integration with overhauled

YuKKi-OS acts as the caller. `overhauled` is the broker/execution side.

Current YuKKi-OS broker contract:

- raw TCP
- 4-byte big-endian length prefix
- JSON request body matching `BrokerTask`
- JSON response body matching `BrokerResult`
- default max frame `65536` bytes in either direction
- connect timeout `3000 ms`, whole-request timeout `5000 ms`
- one connection per submission

Request fields:

```json
{
  "task_id": "task-123",
  "source": "yukki",
  "destination": "overhauled",
  "kind": "inference",
  "priority": 5,
  "timeout_ms": 3000,
  "payload": {
    "model_id": 42
  }
}
```

Response fields:

```json
{
  "task_id": "task-123",
  "status": "ok",
  "gpu_id": 1,
  "execution_ms": 12,
  "result": {
    "tensor": [2.0, 4.0]
  }
}
```

Important caveats:

- `task_id` must round-trip exactly.
- `status` must be non-empty.
- `payload` may be any JSON value except `null`.
- For non-loopback deployment, place the broker hop behind an authenticated
  proxy, mTLS sidecar, or service mesh. YuKKi-OS does not do this for you.

---

## systemd-style service examples

Bootstrap unit:

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
RestartSec=2s
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/yukki

[Install]
WantedBy=multi-user.target
```

Peer unit:

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
RestartSec=2s
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/yukki

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now yukki-bootstrap.service
sudo systemctl enable --now yukki-peer.service
```

These units are examples only; tighten sandboxing further if it is compatible
with your host policy.

---

## Health, logging, and verification

Basic checks:

```bash
systemctl status yukki-bootstrap.service --no-pager
journalctl -u yukki-bootstrap.service -n 50 --no-pager
ss -tlnp | grep 7660
```

For a peer:

```bash
systemctl status yukki-peer.service --no-pager
journalctl -u yukki-peer.service -n 50 --no-pager
```

What to verify:

- bootstrap socket is listening on the expected address
- peer connects and receives fleet updates
- broker endpoint is reachable only through the intended local or authenticated
  boundary
- `RUST_LOG=debug` increases JSON log detail when troubleshooting

---

## Upgrades and rollback

Recommended upgrade flow:

1. build the new binary in a fresh checkout or clean working tree
2. install it alongside the existing deployed binary
3. back up current env files and service units
4. restart bootstrap during a maintenance window
5. restart peers after bootstrap is healthy

Example:

```bash
cd /srv/yukki/YuKKi-OS
git pull --ff-only
cargo build --release
sudo cp /usr/local/libexec/yukki/yukki_core_node /usr/local/libexec/yukki/yukki_core_node.prev
sudo install -o root -g root -m 0755 target/release/yukki_core_node /usr/local/libexec/yukki/yukki_core_node
sudo systemctl restart yukki-bootstrap.service yukki-peer.service
```

Rollback:

```bash
sudo cp /usr/local/libexec/yukki/yukki_core_node.prev /usr/local/libexec/yukki/yukki_core_node
sudo systemctl restart yukki-bootstrap.service yukki-peer.service
```

Because current runtime state is in-memory, rollback mainly means restoring the
previous binary and configuration, then re-establishing peer sessions.

---

## Backup

Back up:

- `/etc/yukki/*.env`
- any local service unit overrides under `/etc/systemd/system/`
- the deployed binary you are running
- your checked-out repository revision or release artifact

Do **not** treat runtime memory as durable state; plan for clean bootstrap/peer
reconnection after restarts.

---

## Troubleshooting

- **Peer gets `Connection refused`:** confirm bootstrap is started first and
  listening on the expected port (`ss -tlnp | grep 7660`).
- **Immediate authentication failure:** confirm every node has the same
  64-character `YUKKI_PSK_HEX`.
- **Broker timeouts:** verify the proxy/service-mesh endpoint is reachable and
  that `YUKKI_BROKER_CONNECT_TIMEOUT_MS` / `YUKKI_BROKER_REQUEST_TIMEOUT_MS`
  match observed latency.
- **Oversized broker payloads:** reduce payload size or coordinate a larger
  `YUKKI_BROKER_MAX_FRAME_BYTES` on both sides of the boundary.
- **Need more detail:** set `RUST_LOG=debug` in the env file and restart the
  service.

See also:

- [README.md](../README.md)
- [DEPLOYMENT.md](DEPLOYMENT.md)
- [SECURITY.md](SECURITY.md)
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
