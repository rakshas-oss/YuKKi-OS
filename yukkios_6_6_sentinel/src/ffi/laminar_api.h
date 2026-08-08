/* laminar_api.h — YuKKi OS v6.6.0 Sentinel Mesh ABI
 * Architect: Aditya Muralidhar (Rakshas International Unlimited)
 * License: GPL-3.0
 */
#ifndef LAMINAR_API_H
#define LAMINAR_API_H

#include <stdint.h>
#include <stddef.h>

/* SpatiotemporalFrame — binary data-plane frame produced by the Lorenz core.
 * Must match the #[repr(C, packed)] struct in main.rs exactly.
 * Total size: 8+8+8+8+8+8+8+4+4+8+16 = 88 bytes.
 */
#pragma pack(push, 1)
typedef struct {
    uint64_t seq_id;
    double   x;
    double   y;
    double   z;
    double   u;
    double   v;
    double   w;
    float    fluidity;
    float    drag;
    double   divergence;
    uint8_t  payload[16];
} SpatiotemporalFrame;
#pragma pack(pop)

/* --- Lorenz engine --- */
void chaos_engine_reseed(double sigma, double rho, double beta,
                         double x0, double y0, double z0);

void weave_spatiotemporal_frame(uint64_t seq,
                                const uint8_t *payload_src,
                                SpatiotemporalFrame *out_frame);

/* --- ChaCha20 polymorphic payload weave (v6.6.0) --- */

/* Weave a polymorphic payload: XOR plaintext with a ChaCha20-derived
 * keystream seeded from the current Lorenz state and the given nonce.
 * out must point to a buffer of at least len bytes.
 * Returns 0 on success, -1 on invalid args.
 */
int chacha_weave_payload(const uint8_t *nonce12,
                         const uint8_t *shared_key32,
                         const uint8_t *plaintext,
                         size_t len,
                         uint8_t *out);

/* --- Sentinel quarantine (v6.6.0) --- */

/* Mark node as quarantined (layer 1 soft + layer 2 hard). */
void sentinel_quarantine_node(const char *node_uuid);

/* Remove quarantine. */
void sentinel_release_node(const char *node_uuid);

/* Returns 1 if quarantined (either layer), 0 otherwise. */
int sentinel_is_quarantined(const char *node_uuid);

/* Returns 2 if hard-quarantined, 1 if soft-quarantined, 0 if clear. */
int sentinel_quarantine_level(const char *node_uuid);

#endif /* LAMINAR_API_H */
