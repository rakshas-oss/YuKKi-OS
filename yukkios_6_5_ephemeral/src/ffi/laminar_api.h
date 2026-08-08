/* LAMINAR FLOW API - v6.5.0 (Ephemeral Mesh Edition) */
#ifndef LAMINAR_API_H
#define LAMINAR_API_H

#include <stdint.h>

/* ---------------------------------------------------------------------------
 * Portability: packing and 8-byte alignment across GCC/Clang and MSVC.
 * On GCC/Clang we use __attribute__((packed, aligned(8))).
 * On MSVC we rely on #pragma pack + __declspec(align(8)).
 * --------------------------------------------------------------------------- */
#if defined(_MSC_VER)
#  define LAMINAR_PACKED_ALIGNED __declspec(align(8))
#elif defined(__GNUC__) || defined(__clang__)
#  define LAMINAR_PACKED_ALIGNED __attribute__((packed, aligned(8)))
#else
#  define LAMINAR_PACKED_ALIGNED
#endif

#pragma pack(push, 1)

/* Strict 88-byte hyper-aligned tensor packet — ABI-stable between Rust and C. */
typedef struct LAMINAR_PACKED_ALIGNED {
    uint64_t seq_id;       /* 8  bytes */
    double   x, y, z;     /* 24 bytes — spatial coords */
    double   u, v, w;     /* 24 bytes — velocity / temporal drift */
    float    fluidity;    /* 4  bytes */
    float    drag;        /* 4  bytes */
    double   divergence;  /* 8  bytes */
    uint8_t  payload[16]; /* 16 bytes — telemetry / encrypted segment */
} SpatiotemporalFrame;   /* Total: 88 bytes */

#pragma pack(pop)

/* ---------------------------------------------------------------------------
 * OOB Integrity API — rolling hash, 60-frame sync, quarantine
 * ---------------------------------------------------------------------------
 * NOTE: oob_fnv1a_rolling_hash is an FNV-1a derivative for lightweight OOB
 * integrity checks; it is NOT a BLAKE3 implementation and makes no full
 * cryptographic guarantees.
 * --------------------------------------------------------------------------- */
uint64_t oob_fnv1a_rolling_hash(uint64_t seed, const uint8_t *data, uint32_t len);
void     oob_integrity_update(uint64_t seq, const uint8_t *payload, uint32_t len);
int      oob_sync_check(uint64_t seq);
void     oob_quarantine_node(const char *node_uuid);
int      oob_is_quarantined(const char *node_uuid);

/* ---------------------------------------------------------------------------
 * Core Lorenz / Weave API
 * --------------------------------------------------------------------------- */
void chaos_engine_init(double sigma, double rho, double beta);
void chaos_engine_reseed(double sigma, double rho, double beta,
                         double x0, double y0, double z0);
void generate_lorenz_step(double dt);
void weave_spatiotemporal_frame(uint64_t seq, const uint8_t *payload_src,
                                SpatiotemporalFrame *out_frame);

/* ---------------------------------------------------------------------------
 * Ephemeral Mesh additions — v6.5.0
 * ---------------------------------------------------------------------------
 * ephemeral_derive_session_key: KDF shim that mixes an X25519 shared secret
 *   with the current Lorenz state to produce a 32-byte session key.
 *   NOTE: out_key must point to a caller-allocated 32-byte buffer.
 * --------------------------------------------------------------------------- */
void ephemeral_derive_session_key(const uint8_t *shared_secret_32,
                                  uint8_t *out_key_32);

#endif /* LAMINAR_API_H */
