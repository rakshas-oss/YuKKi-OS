/* LAMINAR FLOW API - v6.4 (Binary Zero-Drag Spatiotemporal - Legacy Safe) */
#ifndef LAMINAR_API_H
#define LAMINAR_API_H

#include <stdint.h>

/* Pre-C99 / MSVC Fallback Alignment */
#pragma pack(push, 1)

// Strict 88-byte hyper-aligned tensor packet representation
typedef struct __attribute__((packed, aligned(8))) {
    uint64_t seq_id;         // 8 bytes
    double x, y, z;          // 24 bytes (Space)
    double u, v, w;          // 24 bytes (Velocity Vector / Temporal Drift)
    float fluidity;          // 4 bytes
    float drag;              // 4 bytes
    double divergence;       // 8 bytes (Promoted from float to double for strict 8-byte alignment)
    uint8_t payload[16];     // 16 bytes (Telemetry / Encrypted Segment)
} SpatiotemporalFrame;

#pragma pack(pop)

void chaos_engine_init(double sigma, double rho, double beta);
void chaos_engine_reseed(double sigma, double rho, double beta,
                         double x0, double y0, double z0);
void generate_lorenz_step(double dt);
void weave_spatiotemporal_frame(uint64_t seq, const uint8_t* payload_src, SpatiotemporalFrame* out_frame);

#endif
