# Overhauled broker service discovery

YuKKi-OS can advertise an Overhauled broker endpoint through its existing
authenticated peer mesh. This is a bounded, lease-based gossip registry; it is
not a Kademlia/XOR-routing DHT and does not change the mesh's bootstrap topology.

## Enable an advertisement

Start a YuKKi-OS node with the broker endpoint reachable by the other nodes:

```sh
export YUKKI_PSK_HEX=<cluster-psk-hex>
export YUKKI_BROKER_ENDPOINT=broker-01.internal:9090
export YUKKI_BROKER_CAPABILITIES=cpu,gpu,npu
yukki_core_node node <bootstrap-address> <advertised-address>
```

The broker endpoint is optional. Without `YUKKI_BROKER_ENDPOINT`, the node
does not advertise a broker. Use a reachable DNS name or IP address and port;
do not include a URL scheme, path, credentials, or query string.

The node advertises BRK1 and BRK2 support, a 64 KiB frame ceiling, and the
configured capability labels. The default capability is `cpu`. Capability
labels are descriptive only: a client must validate the actual BRK2 response
backend and must not infer accelerator availability from an advertisement.

## Record and lease contract

The version-1 `overhauled.worker-broker` record contains:

- stable service UUID and advertising YuKKi node UUID
- endpoint, protocol versions, capability labels, and maximum frame size
- issue and expiry timestamps, message UUID, and remaining gossip hops

Records are validated before insertion. Leases are limited to 300 seconds;
the node refreshes its advertisement every 30 seconds with a 90-second lease.
The registry expires stale entries and is bounded to 4,096 services. Gossip
forwarding is bounded to eight hops and deduplicated by message UUID.

The library API is exported from `yukkios::broker_discovery`:
`BrokerServiceRecord` and `BrokerServiceRegistry`. Consumers should call
`upsert` only for records received over the authenticated peer channel and
use `list(now_unix)` or `get(service_id, now_unix)` to obtain non-expired
records.

## Trust and execution boundary

The existing mesh encrypts and authenticates connections using the cluster
PSK. This remains a shared-cluster-secret trust model: every holder of the PSK
can participate. The service record itself is not a signed identity
credential, and discovery does not authorize task execution.

Overhauled BRK1/BRK2 TCP is still not authenticated or encrypted. Do not expose
the broker listener directly to untrusted networks. Place it behind an
independently authenticated mTLS proxy/service mesh or a private trusted
network, and advertise only the protected endpoint. YuKKi-OS must enforce
broker admission policy independently of record discovery.

The record exposes coarse service capabilities only. Do not publish CPU IDs,
NUMA node IDs, cache topology, raw affinity masks, or tenant information.

## What this does not provide

- Kademlia or another distributed hash-table routing algorithm
- direct broker-side DHT participation or autonomous endpoint registration
- per-peer certificates, key rotation, or per-service authorization
- authenticated BRK2 transport, remote cancellation, or proof of accelerator use
- durable registry persistence across node restarts

The bootstrap node currently relays service announcements to connected peers.
A future DHT implementation can replace the relay/lookup mechanism while
preserving this versioned service-record contract.
