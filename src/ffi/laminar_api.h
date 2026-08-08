/* LAMINAR FLOW API - v6.4.3 (Binary Zero-Drag Spatiotemporal - Legacy Safe) */
#ifndef LAMINAR_API_H
#define LAMINAR_API_H

#include <stdint.h>

/* ---------------------------------------------------------------------------
 * Portability: packing and 8-byte alignment across GCC/Clang and MSVC.
 * ---------------------------------------------------------------------------
 * On GCC/Clang we use __attribute__((packed, aligned(8))).
 * On MSVC there is no aligned packed attribute, so we rely on #pragma pack
 * (already applied below) and __declspec(align(8)).
 * --------------------------------------------------------------------------- */
#if defined(_MSC_VER)
#  define LAMINAR_PACKED_ALIGNED __declspec(align(8))
#elif defined(__GNUC__) || defined(__clang__)
#  define LAMINAR_PACKED_ALIGNED __attribute__((packed, aligned(8)))
#else
#  define LAMINAR_PACKED_ALIGNED
#endif

/* Pre-C99 / MSVC Fallback Alignment */
#pragma pack(push, 1)

// Strict 88-byte hyper-aligned tensor packet representation
typedef struct LAMINAR_PACKED_ALIGNED {
    uint64_t seq_id;         // 8 bytes
    double x, y, z;          // 24 bytes (Space)
    double u, v, w;          // 24 bytes (Velocity Vector / Temporal Drift)
    float fluidity;          // 4 bytes
    float drag;              // 4 bytes
    double divergence;       // 8 bytes (Promoted from float to double for strict 8-byte alignment)
    uint8_t payload[16];     // 16 bytes (Telemetry / Encrypted Segment)
} SpatiotemporalFrame;

#pragma pack(pop)

/* ---------------------------------------------------------------------------
 * OOB Integrity API — v6.4.3 Out-of-Band Integrity Edition
 * ---------------------------------------------------------------------------
 * oob_fnv1a_rolling_hash: FNV-1a–style rolling hash accumulator.
 *   NOTE: This is an FNV-1a derivative for lightweight OOB integrity checks;
 *   it is NOT a BLAKE3 implementation and makes no cryptographic guarantees.
 * oob_integrity_update:   Feed one frame into the rolling hash state.
 * oob_sync_check:         Returns 1 if the 60-frame sync boundary is reached.
 * oob_quarantine_node:    Mark a node UUID as quarantined/blacklisted.
 * oob_is_quarantined:     Returns 1 if the given node UUID is quarantined.
 * --------------------------------------------------------------------------- */
uint64_t oob_fnv1a_rolling_hash(uint64_t seed, const uint8_t *data, uint32_t len);
void     oob_integrity_update(uint64_t seq, const uint8_t *payload, uint32_t len);
int      oob_sync_check(uint64_t seq);
void     oob_quarantine_node(const char *node_uuid);
int      oob_is_quarantined(const char *node_uuid);

void chaos_engine_init(double sigma, double rho, double beta);
void chaos_engine_reseed(double sigma, double rho, double beta,
                         double x0, double y0, double z0);
void generate_lorenz_step(double dt);
void weave_spatiotemporal_frame(uint64_t seq, const uint8_t* payload_src, SpatiotemporalFrame* out_frame);

#endif
