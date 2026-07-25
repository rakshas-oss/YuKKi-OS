YuKKi OS 4 Release: Changes Since 3.2

YuKKi OS 4 marks a major shift from the 3.x series, focusing on enhanced developer experience and deeper integration for distributed collaboration. While the core security model (mTLS, Dual-Channel Architecture) remains the backbone of the platform, this version introduces significant upgrades to the user interface and the JobbySlotty build system.
Key Changes and New Features in YuKKi OS 4
1. Enhanced Distributed Build System ("JobbySlotty")

The most critical functional update is the introduction of a formal mechanism to share complex project structures, making collaborative compilation much easier.

    NEW: Dependency Manifest Exchange

        We have formalized the process of sharing project build definitions. Peers can now exchange complete, structured dependency manifests.

        New Commands:

            manifest submit <uuid>: Pushes your project's build tree structure to a specified peer.

            manifest get <uuid>: Requests a manifest from a peer, queuing their complex build steps on your system.

        ADI Protocol Update: The custom ADI (Advanced Data Interchange) Protocol now includes a dedicated packet type (P2P_DEP_MANIFEST) for efficient, low-overhead transmission of these manifest files.

2. Configurable Visual Prompt (UI/UX Overhaul)

We've brought the user-facing experience up to modern standards by replacing the classic, simple prompt with a fully configurable visual display that is deeply integrated with the linenoise terminal.

    NEW: Zsh-Style Visual Prompt:

        The prompt is now highly informative, displaying the current time, your user profile, and a status indicator (e.g., ✔).

        Example Prompt: [HH:MM:SS] [profile_name] ✔ >

        Configurable: The yukki_configurator.sh script now offers a clear opt-in option to enable this "enhanced visual prompt."

    Zero Loss of Functionality: This visual upgrade is handled entirely by the robust linenoise library, ensuring you retain full command history and context-aware tab-completion.

3. Zero-Copy Slab / Memory-Pool Bridge (C-core ↔ Rust)

To eliminate high-frequency dynamic heap allocations in the IPC/streaming loop, YuKKi OS 4 introduces a deterministic slab allocator that bridges the C core and the Rust async runtime.

### Architecture

A single contiguous arena is allocated once at start-up via `posix_memalign` (64-byte aligned).  The arena is carved into fixed-size blocks that are managed through an **intrusive LIFO free-list** stored inside idle blocks themselves (zero overhead).  A `pthread_mutex_t` makes all operations safe from multiple threads.

The Rust side wraps raw block pointers in `ZeroCopyBuffer`, a struct with a `Drop` implementation that **returns** the block to the C pool instead of calling the Rust allocator.

### Key files

| File | Role |
|------|------|
| `native/include/yukki/mempool.h` | C API declarations and struct definitions |
| `native/ffi/yukki_mempool.c` | Pool implementation (init, acquire, release, destroy) |
| `src/mempool.rs` | Safe Rust wrapper exposing `ZeroCopyBuffer` |
| `build.rs` | Compiles the C file via the `cc` crate and links `pthread` |

### Initialisation

The pool is initialised in `main()` before any async tasks are spawned.  Two environment variables control sizing:

| Variable | Default | Description |
|----------|---------|-------------|
| `YUKKI_POOL_BLOCK_SIZE` | `1048576` (1 MiB) | Size of each block in bytes |
| `YUKKI_POOL_BLOCK_COUNT` | `16` | Number of pre-allocated blocks |

Example — use 32 blocks of 512 KiB each (16 MiB total):

```
YUKKI_POOL_BLOCK_SIZE=524288 YUKKI_POOL_BLOCK_COUNT=32 ./yukkios_4_rust client …
```

### Acquire / Use / Release via Drop

```rust
// Acquire a buffer from the pool (returns None when exhausted).
if let Some(mut buf) = mempool::ZeroCopyBuffer::acquire(data.len()) {
    let slice = buf.as_mut_slice();
    slice[..data.len()].copy_from_slice(&data);
    socket.write_all(&slice[..data.len()]).await?;
    // buf is automatically returned to the pool here — no free() needed.
}
```

### Pool exhaustion

`YuKKi_AcquireBuffer` returns `NULL` (and `ZeroCopyBuffer::acquire` returns `None`) when all blocks are in use.  The `send_p2p_message` function falls back to a standard `Vec`-backed write in this case, so the system continues to function under load spikes.

### Tuning guidance

* **block_size**: Set to the maximum expected message or chunk size.  The default 1 MiB matches `P2P_BUF_SIZE` in the Rust code.  Smaller values reduce RSS; larger values reduce copy overhead for big transfers.
* **block_count**: Set to the maximum number of concurrent in-flight messages you expect.  At 16 blocks × 1 MiB = 16 MiB reserved upfront — a small, predictable footprint.
* If `block_size < sizeof(yukki_mempool_node_t)` the C init will abort with a clear error message.

4. General Platform and Documentation Updates

    Version Bump: The major version number reflects the fundamental commitment to these new capabilities and the move away from the 3.x framework.

    Compliance Framework: Minor refinements were made to the CRTC and PIPEDA compliance logging procedures to better track user consent specific to the new manifest exchange feature.
