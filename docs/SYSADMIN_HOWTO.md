# YuKKi-OS v6.13.0 — System Administration How-to

> Release candidate: the v6.13.0 tag and release archives remain subject to the
> required CI and release qualification gates. This guide describes the
> implementation on the v6.13.0 candidate branch.

## 1. Scope and deployment components

YuKKi-OS provides separate deployment surfaces:

- **Native node:** authenticated peer mesh, bootstrap and node roles.
- **Stream gateway:** authenticated HTTP/WebSocket access to a node's local
  in-memory stream registry, or an independent store when run standalone.
- **WASI guest worker:** isolated `wasm32-wasip1` artifact hosted by the native
  Wasmtime runtime.
- **Browser client:** static `wasm32-unknown-unknown` verifier/spatial app;
  it is not the native node or the WASI guest.
- **Broker clients:** a generic JSON broker client and a separate
  BRK1/BRK2 + WSM1 adapter for the Overhauled execution tier.

The peer mesh, gateway, generic broker client and Overhauled adapter are
separate transport paths. Configuring one does not start the others.

## 2. Toolchain and native build

The repository pins Rust 1.98.1 in `rust-toolchain.toml`. Install the pinned
toolchain and the native C compiler required by the C FFI build.

From the repository root:

```bash
rustup show
cargo build --release --locked
cargo test --locked
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
```

The native executable is `target/release/yukki_core_node`. The library crate
is `yukkios`. The separate browser and guest-worker manifests have their own
build/test steps below.

## 3. Create the service account and protected configuration

Example Linux account and directories:

```bash
sudo useradd --system --home /var/lib/yukki --shell /usr/sbin/nologin yukki
sudo install -d -o yukki -g yukki -m 0750 /var/lib/yukki
sudo install -d -o root -g yukki -m 0750 /etc/yukki
```

Create one random 32-byte cluster PSK. The same cluster secret must be
provisioned securely to every peer that joins this mesh:

```bash
sudo sh -c 'umask 027; printf "YUKKI_PSK_HEX=%s\nRUST_LOG=info\n" "$(openssl rand -hex 32)" > /etc/yukki/cluster.env'
sudo chown root:yukki /etc/yukki/cluster.env
sudo chmod 0640 /etc/yukki/cluster.env
```

Protect and distribute the generated file through your approved secret
management process. Do not commit it or paste its contents into logs or
tickets. `YUKKI_PSK_HEX` must be exactly 64 hexadecimal characters.

The peer mesh derives session keys from X25519, HKDF-SHA256 and this shared
PSK, then uses directional ChaCha20-Poly1305. This is a shared-cluster-secret
trust model, not per-peer identity or key rotation. Rotate the PSK as a
coordinated cluster operation.

## 4. Configure and run the peer mesh

Bootstrap node:

```bash
./target/release/yukki_core_node bootstrap 10.0.0.10:7660
```

Peer node:

```bash
./target/release/yukki_core_node node 10.0.0.10:7660 10.0.0.21:9999
```

Both commands require `YUKKI_PSK_HEX`. The bootstrap address is the actual
bootstrap listener; the advertised address must be reachable by the peers
that use it. Bind only to the interfaces required by the deployment and
restrict ingress with host/network firewall rules.

The current peer transport uses a four-byte big-endian length prefix, a
maximum 64 KiB plaintext message, a 10-second handshake timeout and 30-second
I/O timeouts. The bootstrap accepts at most 128 concurrent connections.
Peer registry state is in memory and is not persisted across process restart.

## 5. Deploy with systemd

Use separate units and environment files for the bootstrap and peer roles.
A bootstrap unit example:

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
EnvironmentFile=/etc/yukki/cluster.env
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

A peer unit changes the description, address arguments and optional node
gateway environment file:

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
EnvironmentFile=/etc/yukki/cluster.env
EnvironmentFile=-/etc/yukki/node.env
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

If the peer should expose its in-process stream gateway, create
`/etc/yukki/node.env` with a high-entropy `YUKKI_GATEWAY_TOKEN` and the
desired `YUKKI_GATEWAY_LISTEN`. Setting the token causes the node process to
start its embedded gateway. The default listen address is
`127.0.0.1:7670`. Generate the file with restricted permissions:

```bash
sudo sh -c 'umask 027; printf "YUKKI_GATEWAY_TOKEN=%s\nYUKKI_GATEWAY_LISTEN=127.0.0.1:7670\n" "$(openssl rand -hex 32)" > /etc/yukki/node.env'
sudo chown root:yukki /etc/yukki/node.env
sudo chmod 0640 /etc/yukki/node.env
```

After placing the executable at `/usr/local/libexec/yukki/yukki_core_node`
and creating the unit files:

```bash
sudo chown root:root /usr/local/libexec/yukki/yukki_core_node
sudo chmod 0755 /usr/local/libexec/yukki/yukki_core_node
sudo systemctl daemon-reload
sudo systemctl enable --now yukki-bootstrap.service
# Enable the peer service on peer hosts:
sudo systemctl enable --now yukki-peer.service
```

Do not configure a standalone gateway and an embedded node gateway on the
same address/port.

## 6. Configure the stream gateway

The standalone gateway command is:

```bash
export YUKKI_GATEWAY_TOKEN="$(openssl rand -hex 32)"
./target/release/yukki_core_node gateway 127.0.0.1:7670
```

The bearer token must contain 1–4096 visible characters. The standalone
gateway creates its own in-memory store. In contrast, the gateway started by
the `node` command shares that node's local stream store and registry.

Relevant settings:

| Setting | Behavior |
|---|---|
| `YUKKI_GATEWAY_TOKEN` | Bearer token required by protected gateway APIs; also enables the node's embedded gateway |
| `YUKKI_GATEWAY_LISTEN` | Embedded node gateway bind address; default `127.0.0.1:7670` |
| `YUKKI_GATEWAY_ENDPOINT` | Default address used by `streams list` and `streams tune`; default `127.0.0.1:7670` |
| `YUKKI_GATEWAY_CORS_ORIGINS` | Comma-separated exact browser origins allowed for cross-origin GET/preflight requests |

The static `/dashboard` HTML page is public. Stream metadata and chunk APIs
require the bearer token unless `--insecure-dev` is selected. Use
`--insecure-dev` only for local development; it bypasses the gateway auth
gate and is not a production configuration.

The gateway currently caps accepted connections at 128, HTTP request handling
at 30 seconds, chunk range reads at eight chunks, and WebSocket idle time at
60 seconds with 20-second pings. Media streams are in-memory and bounded;
this is not durable media storage. The gateway does not terminate TLS and
does not expose a built-in health or metrics endpoint.

The command-line stream clients are:

```bash
YUKKI_GATEWAY_TOKEN="$YUKKI_GATEWAY_TOKEN" ./target/release/yukki_core_node streams list
YUKKI_GATEWAY_TOKEN="$YUKKI_GATEWAY_TOKEN" ./target/release/yukki_core_node streams tune camera-stream --from 0
```

`streams list` can take an explicit gateway address as its optional second
argument. `streams tune` uses `YUKKI_GATEWAY_ENDPOINT` for its gateway
address and writes received chunk payloads to stdout.

## 7. Publish the browser application

Build the independent browser WASM module:

```bash
rustup target add wasm32-unknown-unknown
cargo fmt --manifest-path browser-wasm/Cargo.toml -- --check
cargo test --manifest-path browser-wasm/Cargo.toml --locked
cargo clippy --manifest-path browser-wasm/Cargo.toml --locked --target wasm32-unknown-unknown -- -D warnings
cargo build --manifest-path browser-wasm/Cargo.toml --release --locked --target wasm32-unknown-unknown

mkdir -p browser-wasm/dist
cp browser-wasm/index.html browser-wasm/app.js browser-wasm/styles.css browser-wasm/dist/
cp browser-wasm/target/wasm32-unknown-unknown/release/yukki_browser_core.wasm browser-wasm/dist/
```

Publish the four files from `browser-wasm/dist/` together under a static
HTTPS origin. Serve `.wasm` with `Content-Type: application/wasm`. Do not
open the page with `file://`; the browser fetches the WASM module from the
static origin.

For same-origin hosting, reverse-proxy the gateway routes under the static
site origin. For separate origins, configure the gateway with exact,
comma-separated origins, for example:

```bash
YUKKI_GATEWAY_CORS_ORIGINS=https://dashboard.example.com
```

Wildcards are rejected. CORS is not authentication. Keep the bearer token in
the browser Authorization header and use HTTPS; never place it in a URL. The
browser application keeps the token in page memory and uses authenticated
HTTP range reads. It does not use the browser WebSocket API because it cannot
set the required Authorization header.

The browser's MMO entity store and simplified sample path are local to the
WASM instance. They are not persisted by the gateway and are not automatically
populated from gateway streams.

## 8. Build, validate, and integrate the WASI guest worker

The WASI Preview 1 worker is a separate artifact, not the browser application or native node. Build it and run both its unit tests and the host-side Wasmtime integration test:

```bash
rustup target add wasm32-wasip1
./scripts/build_guest_worker.sh --check
```

Output: `guest-worker/target/wasm32-wasip1/release/yukki_guest_worker.wasm`.

The accepted guest ABI is deliberately narrower than a general-purpose WASI environment. The native host checks the module size (4 MiB maximum), allowed imports, required exports, fuel, stack, memory and execution deadline before invoking the worker. The permitted imports are `env.wasmtime_yield_xpu` and `env.yukki_select_stream`; the required exports are `memory` and `execute_inference_pipeline`. The host-side tensor input ceiling is 16 MiB, guest linear memory is capped at 64 MiB, fuel defaults to 10,000,000, and the execution watchdog is 10 seconds.

The shipped worker is a small input-validation/channel-lock/XPU-yield adapter with a non-cryptographic integrity hash. It is not a language model, tokenizer, `llama.cpp` build, or weights executor.

### Deployment handler versus an HTTP deployment service

`yukkios::wasm_ingest::handle_deploy` is a library request handler. It is **not** a route served by `yukki_core_node`, and the repository does not ship the HTTP frontend/authentication layer. If an application exposes a route such as `POST /v1/sandbox/deploy`, that application must authenticate the caller first and then invoke the handler.

The handler validates the content type, channel ID, and Wasm ABI, then performs a smoke run with a 16-byte zero tensor. A successful response means the candidate passed that validation/smoke run; it does not mean the binary has been stored, registered as a persistent worker, or deployed for subsequent requests. The application owns artifact storage, authorization, version policy and any persistent deployment endpoint.

For actual one-shot work, the host application calls `wasm_ingest::run_guest` or `run_guest_with_streams` with the real tensor and an `XpuHandler` callback. The latter can provide bounded YKMC chunks from a configured in-process media store. The callback is supplied by the host; it is not automatically wired to the Overhauled GPU/NPU adapter.

### Version replacement and module compilation

The library-level `ModuleLifecycleManager` can validate and register a version, then coordinate a hot-swap:

```rust
let lifecycle = ModuleLifecycleManager::new(Duration::from_secs(5));
lifecycle.prepare_version("worker", "1.2.0", &wasm_bytes, None)?;
lifecycle.hotswap("worker", "1.2.0").await?;
```

`prepare_version` compiles/validates the candidate synchronously with Wasmtime, but drops the compiled `Module` and retains the original bytes. The application must connect the selected version handle to its guest execution closure; the manager does not itself instantiate the guest. Hot-swap provides optional serialized application-state handoff, an active-version routing switch, and quiesce/drain/release ordering. It does not merge compiled code, link multiple modules, move live Wasm memory, or migrate arbitrary GPU state. There is no built-in module-management CLI.

### Compose several policy modules into live programs

The native composition API is a library integration. It does not add a
`yukki_core_node` subcommand or public HTTP deployment route. Install WABT so
the `wat2wasm` compiler is available, then build the checked-in core-Wasm
examples from the repository root:

```bash
wat2wasm examples/wasm-composition/math-kernel.wat -o math-kernel.wasm
wat2wasm examples/wasm-composition/risk-score.wat -o risk-score.wasm
wat2wasm examples/wasm-composition/risk-alert.wat -o risk-alert.wasm
```

Keep these generated artifacts with the application release and record their
hashes in your deployment's artifact inventory. Load the JSON manifest and the
module bytes in the embedding Rust application, then pass them to
`CompositionRuntime::prepare_json`.

The example directory `examples/wasm-composition/` contains two policies
that reuse the same compiled `math-kernel:1.0.0` artifact. The example
manifest configures four replicas for `risk-score-policy` and two for
`risk-alert-policy`. Both declare `stateless: true`, because each replica
has independent guest memory and mutable globals. Omit the replica fields
for the safe one-replica default; do not fan out stateful programs.

After staging, call `CompositionRuntime::activate` once to route all programs
in the release together. Use `call` for time-weighted selection by service
time, or `call_with_spatial_key` to add a stable logical affinity key (such
as a tenant, entity, tile, sensor or partition ID). The scheduler updates service time as a 7/8 previous estimate plus 1/8 latest
sample. An optional u64 logical key is mapped to a stable preferred replica
with a SplitMix64 finalizer. Other replicas receive a 25% service-time penalty,
but a materially faster replica can win; a rotating cursor breaks ties. This is
logical affinity, not physical NUMA pinning or geographic routing.

Every replica has its own Wasmtime Store. The runtime uses non-blocking Store
admission: busy replicas are skipped; when every replica is busy the call
returns `CompositionError::ProgramSaturated` immediately rather than
waiting behind a guest. This reduces head-of-line blocking when spare
replicas exist, but it is not a promise of zero stalls under full saturation.
Use bounded retries/backpressure and inspect `replica_metrics` before
increasing pool sizes. Fuel is an instruction budget, not a wall-clock
deadline.

Run focused tests with:

```bash
cargo test wasm_composition
cargo test temporal_spatial_scheduler
```

The application owns artifact storage, access control, version selection and
any HTTP deployment API. Composition v1 links declared function imports
only; it rejects imported memory/global/table resources, host/WASI imports
and cyclic graphs. Identical module bytes share an in-memory SHA-256 compile
cache. Per-call fuel, memory, table, instance and replica limits remain
enforced.

For the manifest schema, end-to-end API example, hot-update process and
resource limits, see [WASM_PROGRAM_COMPOSITION.md](WASM_PROGRAM_COMPOSITION.md).

For the minimal host-side sequence, the application loads the manifest and
module binaries, calls `prepare_json` to compile, validate, link and
instantiate the complete release, and only then calls `activate`. New calls
can use `call` for service-time-only routing or `call_with_spatial_key` for
a stable logical shard preference. The application owns authentication,
artifact storage, version selection and the Rust code that invokes this API.
Use one replica by default. Set `replicas` above one only when the policy is
truly stateless across independent guest memories and mutable globals.

## 9. Configure broker integrations deliberately

YuKKi-OS has two separate broker client configurations.

### Generic JSON broker client

`src/broker_client.rs` uses a raw TCP connection per submission with a
four-byte big-endian length prefix and JSON request/response body. Defaults:

- `YUKKI_BROKER_ENDPOINT`: `127.0.0.1:9000`
- `YUKKI_BROKER_CONNECT_TIMEOUT_MS`: 3000 ms
- `YUKKI_BROKER_REQUEST_TIMEOUT_MS`: 5000 ms
- `YUKKI_BROKER_MAX_FRAME_BYTES`: 65536 bytes
- `YUKKI_BROKER_TRANSPORT_SECURITY`: `plaintext-boundary`

Connect and request timeouts must be 1..=600000 ms. Individual broker task
timeouts must be 1..=300000 ms. This client configuration is used by library
consumers that construct the generic broker client; it does not start a
broker server or automatically route the native peer-mesh CLI through it.

`YUKKI_BROKER_TRANSPORT_SECURITY=authenticated-proxy` is descriptive
configuration metadata. The client still uses raw TCP; the setting does not
enable TLS or authenticate a socket.

### Overhauled accelerator adapter

The separate `src/gpu_adapter.rs` integration targets
[rakshas-oss/overhauled](https://github.com/rakshas-oss/overhauled). It uses
the BRK1/v1 or BRK2/v2 binary broker envelope with WSM1 task/lifecycle payloads
where configured. It is disabled by default and is not started automatically
by `yukki_core_node bootstrap` or `node`.

| Setting | Default / behavior |
|---|---|
| `YUKKI_GPU_ADAPTER_ENABLED` | `false`; application must opt in |
| `YUKKI_GPU_BROKER_ENDPOINT` | `127.0.0.1:9090`; falls back to `YUKKI_BROKER_ENDPOINT` if set |
| `YUKKI_GPU_CONNECT_TIMEOUT_MS` | 3000 ms |
| `YUKKI_GPU_REQUEST_TIMEOUT_MS` | 5000 ms |
| `YUKKI_GPU_QUIESCE_TIMEOUT_MS` | 5000 ms |
| `YUKKI_GPU_MAX_FRAME_BYTES` | 1048576 bytes |
| `YUKKI_GPU_MAX_RETRIES` | 3 |
| `YUKKI_GPU_USE_WSM1` | `false`; selects WSM1 lifecycle-client wiring when enabled |

The adapter's retry backoff defaults to 50 ms. Configure the Overhauled
broker independently and keep its raw TCP endpoint on a trusted network or
behind a separately secured proxy. Adapter enablement means the client is
configured; it does not prove that a GPU or NPU is present or that a request
was executed by one. Inspect the response backend and fallback result.

The host-side NPU opt-in is `YUKKI_NPU_AVAILABLE` (accepted values include
`1`, `true`, and `yes`). It is only an availability declaration for the
host policy; it does not instantiate hardware or guarantee NPU execution.
Physical accelerator availability and dispatch are determined by the
Overhauled broker. CPU is the correctness baseline. CPU retry after
accelerator failure is allowed only when the task profile marks it safe.

## 10. Run native dataset and eigensolver workloads

The native benchmark manifest under `examples/benchmark-datasets/` drives
actual JSONL source records and benchmark profiles. The shipped examples are
deterministic synthetic fixtures; replace them with governed data sources for
deployment measurements and preserve the original units, timestamps,
provenance and quality metadata.

Run all configured dataset/profile pairs:

```bash
cargo run --release --bin yukki_dataset_bench -- --manifest examples/benchmark-datasets/manifest.json --dataset all --profile all --output benchmark-results.json

cargo run --release --bin yukki_eigensolver_bench -- --manifest examples/benchmark-datasets/manifest.json --dataset all --profile all --output eigensolver-results.json
```

The general multivariate data-source schema is not the native benchmark
manifest. Convert/validate source-catalogue entries into the benchmark
manifest's dataset and JSONL mappings before invoking these commands. The
dataset benchmark reports measured candidates and selected batch/worker
policies; the working-set result is an estimate, not process RSS.

The eigensolver is a CPU reference implementation for finite real-symmetric
matrices of dimensions 1..=64. It is not a general complex or non-symmetric
solver and does not claim GPU/NPU acceleration. These benchmarks do not
establish production domain-model validity, flight safety, investment
performance, wall-power reduction or OPEX savings.

For timing baselines use the same machine, toolchain, data, feature set and
power profile. See [BENCHMARKING.md](BENCHMARKING.md) and
[BENCHMARK_DRIVEN_DATASETS.md](BENCHMARK_DRIVEN_DATASETS.md).

### 10.1. Verify the browser-WASM to BRK2 benchmark bridge

This is an optional local qualification check, not a production service
configuration. It uses a standalone Node benchmark client and a CPU-only
Overhauled broker. It does not require enabling the YuKKi GPU adapter or
WSM1 lifecycle mode.

Assuming the two repositories are sibling directories, build the broker
from the YuKKi-OS repository root (adjust the path if your checkout layout
differs):

~~~bash
cmake -S ../overhauled -B ../overhauled/build-cpu -DCMAKE_BUILD_TYPE=Release -DBUILD_BROKER=ON -DENABLE_CUDA=OFF -DENABLE_TENSORRT=OFF
cmake --build ../overhauled/build-cpu --parallel
ctest --test-dir ../overhauled/build-cpu --output-on-failure
~~~

Start the broker in a separate terminal:

~~~bash
../overhauled/build-cpu/broker_server 9090 --cpu-only
~~~

Back in the YuKKi-OS root, build and run the benchmark:

~~~bash
rustup target add wasm32-unknown-unknown
cargo build --manifest-path browser-wasm/Cargo.toml --release --locked --target wasm32-unknown-unknown
node browser-wasm/bench/run.mjs --quick --broker-host 127.0.0.1 --broker-port 9090 --broker-device cpu --output browser-wasm-brk2.json
~~~

A successful run confirms that the local WASM workload completed and that
the benchmark client received and validated correlated BRK2 broker responses.
Inspect the JSON report for backend counts, selected GPU IDs, fallback count,
and request latency. On the CPU-only configuration, the expected backend is
CPU and selected GPU IDs should be empty. A different result should be
investigated rather than normalized away.

The benchmark's TCP protocol is not authenticated or encrypted. Keep the
listener on loopback or a trusted, independently secured network. Do not
expose it directly to the public internet. This check does not validate
browser hosting, HTTP gateway behavior, WSM1 guest execution, NUMA scheduling,
or physical GPU/NPU execution.


## 11. Health checks, logging and troubleshooting

There is no built-in peer-mesh or gateway HTTP health endpoint and no
built-in metrics endpoint. Use process state, logs and listener checks:

```bash
systemctl status yukki-bootstrap.service --no-pager
journalctl -u yukki-bootstrap.service -n 100 --no-pager
ss -tlnp | grep 7660
ss -tlnp | grep 7670
```

Set `RUST_LOG=debug` in the service environment for additional tracing.
Check that peers use the same PSK, the advertised address is reachable, the
gateway token is present, the browser origin matches the exact CORS allow
list, and broker mode/endpoint matches the Overhauled listener configuration.

For common failures, consult [TROUBLESHOOTING.md](TROUBLESHOOTING.md),
[OVERHAULED_INTEROP.md](OVERHAULED_INTEROP.md), and
[ETHOSU_U85_DEPLOYMENT.md](ETHOSU_U85_DEPLOYMENT.md).

## 12. Upgrade and rollback

Do not treat an unqualified release candidate as a stable production release.
Build and qualify an approved commit or release on a staging host first.
Record the deployed commit SHA and preserve the previous executable:

```bash
sudo cp /usr/local/libexec/yukki/yukki_core_node /usr/local/libexec/yukki/yukki_core_node.prev
sudo install -o root -g root -m 0755 target/release/yukki_core_node /usr/local/libexec/yukki/yukki_core_node
sudo systemctl restart yukki-bootstrap.service yukki-peer.service
```

Rollback:

```bash
sudo cp /usr/local/libexec/yukki/yukki_core_node.prev /usr/local/libexec/yukki/yukki_core_node
sudo systemctl restart yukki-bootstrap.service yukki-peer.service
```

Keep configuration and secrets under the same access controls during upgrades.
Peer registry and stream data are in-memory; restarting a process does not
restore them from disk.
