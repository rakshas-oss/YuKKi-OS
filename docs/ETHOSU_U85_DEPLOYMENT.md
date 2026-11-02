# Ethos-U85 deployment boundary

YuKKi-OS is the control plane. Physical Ethos-U85 execution is provided by
the Overhauled broker's opt-in mainline Linux DRM backend; the old
`src/drivers/ethosu85_async.rs` source is an orphaned placeholder and is not
a Linux DRM driver. It must not be used as a hardware execution path.

## Build the broker

On a Linux host whose kernel exposes the mainline Ethos-U DRM UAPI:

```sh
cmake -S . -B build \
  -DENABLE_ETHOSU_DRM=ON \
  -DENABLE_CUDA=OFF \
  -DENABLE_TENSORRT=OFF \
  -DBUILD_BROKER=ON
cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure
```

Prepare a `YU85BND1` bundle from a Vela-compiled command stream and the
associated memory-region layout. The bundle format, quantization fields,
bounds, and tensor mapping are specified in the Overhauled repository at
`docs/ETHOSU_U85_BUNDLE.md`.

Start the broker with:

```sh
./build/broker_server 9090 --npu-ethosu-bundle model.yu85
```

If automatic render-node discovery is unsuitable, select the node explicitly:

```sh
./build/broker_server 9090 \
  --npu-ethosu-bundle model.yu85 \
  --ethosu-device /dev/dri/renderD128
```

YuKKi-OS continues to request the NPU through the existing BRK2
`device_preference=npu` field. No new wire protocol is required. The broker
reports NPU execution only when the DRM executor is enabled and the request
actually completes on that executor. If an eligible request is marked
fallback-safe and hardware execution fails, the existing CPU fallback policy
remains in force.

## Validation

The existing simulated NPU and CPU fallback tests remain the hardware-free
regression path. A successful build or simulator run does not prove physical
U85 execution. Board validation must confirm the kernel UAPI, Vela command
stream compatibility, input/output quantization, and an actual inference
result on the target board.
