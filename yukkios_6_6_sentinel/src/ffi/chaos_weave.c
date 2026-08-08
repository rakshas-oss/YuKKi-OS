/* chaos_weave.c — YuKKi OS v6.6.0 Sentinel Mesh
 * Lorenz attractor core + ChaCha20 polymorphic payload weave + sentinel quarantine
 * Architect: Aditya Muralidhar (Rakshas International Unlimited)
 * License: GPL-3.0
 * C99 compatible
 */

#include "laminar_api.h"
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* =========================================================================
 * Lorenz attractor state
 * ========================================================================= */

static double x_state   = 0.1;
static double y_state   = 0.0;
static double z_state   = 0.0;
static double sigma_p   = 10.0;
static double rho_p     = 28.0;
static double beta_p    = 8.333333333333;

void chaos_engine_reseed(double sigma, double rho, double beta,
                         double x0, double y0, double z0)
{
    sigma_p  = sigma;
    rho_p    = rho;
    beta_p   = beta;
    x_state  = x0;
    y_state  = y0;
    z_state  = z0;
}

static void lorenz_step(double dt)
{
    double dx = sigma_p * (y_state - x_state);
    double dy = x_state * (rho_p - z_state) - y_state;
    double dz = x_state * y_state - beta_p * z_state;

    x_state += dx * dt;
    y_state += dy * dt;
    z_state += dz * dt;

    /* Clamp against NaN / overflow */
    if (x_state != x_state || x_state > 1e308 || x_state < -1e308) x_state = 0.1;
    if (y_state != y_state || y_state > 1e308 || y_state < -1e308) y_state = 0.0;
    if (z_state != z_state || z_state > 1e308 || z_state < -1e308) z_state = 0.0;
}

void weave_spatiotemporal_frame(uint64_t seq,
                                const uint8_t *payload_src,
                                SpatiotemporalFrame *out_frame)
{
    if (!out_frame) return;

    /* Optionally perturb sigma from first payload byte */
    if (payload_src) {
        sigma_p = 10.0 + (payload_src[0] / 255.0);
    }

    /* Advance Lorenz attractor */
    lorenz_step(0.005);

    out_frame->seq_id     = seq;
    out_frame->x          = x_state;
    out_frame->y          = y_state;
    out_frame->z          = z_state;
    out_frame->u          = x_state * 0.5;
    out_frame->v          = y_state * 0.5;
    out_frame->w          = z_state * 0.5;
    out_frame->fluidity   = (float)(fabs(x_state) / (fabs(x_state) + 1.0));
    out_frame->drag       = (float)(1.0 / (1.0 + fabs(z_state - rho_p)));
    out_frame->divergence = x_state * y_state * z_state;

    /* Populate payload slot */
    if (payload_src) {
        memcpy(out_frame->payload, payload_src, 16);
    } else {
        /* Derive 16-byte payload from Lorenz state */
        double parts[2] = { x_state, y_state };
        memcpy(out_frame->payload, &parts, 16);
    }
}

/* =========================================================================
 * Minimal ChaCha20 keystream (RFC 7539 quarter-round, keystream only)
 * Used for polymorphic payload weaving — NOT a fully validated AEAD impl.
 * ========================================================================= */

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

static void chacha20_quarter_round(uint32_t *a, uint32_t *b,
                                   uint32_t *c, uint32_t *d)
{
    *a += *b; *d ^= *a; *d = ROTL32(*d, 16);
    *c += *d; *b ^= *c; *b = ROTL32(*b, 12);
    *a += *b; *d ^= *a; *d = ROTL32(*d,  8);
    *c += *d; *b ^= *c; *b = ROTL32(*b,  7);
}

static void chacha20_block(const uint32_t key[8],
                           uint32_t counter,
                           const uint32_t nonce[3],
                           uint8_t out[64])
{
    uint32_t state[16];
    /* Constants: "expand 32-byte k" */
    state[0]  = 0x61707865u;
    state[1]  = 0x3320646eu;
    state[2]  = 0x79622d32u;
    state[3]  = 0x6b206574u;
    /* Key */
    memcpy(&state[4],  key,     32);
    /* Counter */
    state[12] = counter;
    /* Nonce */
    state[13] = nonce[0];
    state[14] = nonce[1];
    state[15] = nonce[2];

    uint32_t working[16];
    memcpy(working, state, sizeof(state));

    for (int i = 0; i < 10; i++) {
        chacha20_quarter_round(&working[0], &working[4], &working[8],  &working[12]);
        chacha20_quarter_round(&working[1], &working[5], &working[9],  &working[13]);
        chacha20_quarter_round(&working[2], &working[6], &working[10], &working[14]);
        chacha20_quarter_round(&working[3], &working[7], &working[11], &working[15]);

        chacha20_quarter_round(&working[0], &working[5], &working[10], &working[15]);
        chacha20_quarter_round(&working[1], &working[6], &working[11], &working[12]);
        chacha20_quarter_round(&working[2], &working[7], &working[8],  &working[13]);
        chacha20_quarter_round(&working[3], &working[4], &working[9],  &working[14]);
    }

    for (int i = 0; i < 16; i++) {
        working[i] += state[i];
    }

    memcpy(out, working, 64);
}

int chacha_weave_payload(const uint8_t *nonce12,
                         const uint8_t *shared_key32,
                         const uint8_t *plaintext,
                         size_t len,
                         uint8_t *out)
{
    if (!nonce12 || !shared_key32 || !plaintext || !out || len == 0) return -1;

    uint32_t key[8];
    memcpy(key, shared_key32, 32);

    uint32_t nonce[3];
    memcpy(nonce, nonce12, 12);

    /* Mix Lorenz state into key for polymorphic binding */
    uint8_t lorenz_bytes[24];
    memcpy(lorenz_bytes,      &x_state, 8);
    memcpy(lorenz_bytes + 8,  &y_state, 8);
    memcpy(lorenz_bytes + 16, &z_state, 8);
    for (int i = 0; i < 6; i++) {
        uint32_t lb;
        memcpy(&lb, lorenz_bytes + i * 4, 4);
        key[i % 8] ^= lb;
    }

    uint8_t keystream[64];
    uint32_t counter = 0;
    size_t offset = 0;

    while (offset < len) {
        chacha20_block(key, counter++, nonce, keystream);
        size_t chunk = len - offset;
        if (chunk > 64) chunk = 64;
        for (size_t i = 0; i < chunk; i++) {
            out[offset + i] = plaintext[offset + i] ^ keystream[i];
        }
        offset += chunk;
    }

    return 0;
}

/* =========================================================================
 * Sentinel quarantine registry (dual-layer: soft + hard)
 * ========================================================================= */

#define MAX_QUARANTINE 256
#define UUID_LEN        37   /* 36 chars + NUL */

typedef struct {
    char  uuid[UUID_LEN];
    int   level;  /* 1 = soft, 2 = hard */
} QuarantineEntry;

static QuarantineEntry q_registry[MAX_QUARANTINE];
static int             q_count = 0;

static int find_entry(const char *node_uuid)
{
    for (int i = 0; i < q_count; i++) {
        if (strncmp(q_registry[i].uuid, node_uuid, UUID_LEN - 1) == 0) {
            return i;
        }
    }
    return -1;
}

void sentinel_quarantine_node(const char *node_uuid)
{
    if (!node_uuid) return;
    int idx = find_entry(node_uuid);
    if (idx >= 0) {
        /* Escalate to hard quarantine */
        q_registry[idx].level = 2;
        return;
    }
    if (q_count < MAX_QUARANTINE) {
        strncpy(q_registry[q_count].uuid, node_uuid, UUID_LEN - 1);
        q_registry[q_count].uuid[UUID_LEN - 1] = '\0';
        q_registry[q_count].level = 1;
        q_count++;
    }
}

void sentinel_release_node(const char *node_uuid)
{
    if (!node_uuid) return;
    int idx = find_entry(node_uuid);
    if (idx < 0) return;
    /* Swap with last entry */
    q_registry[idx] = q_registry[--q_count];
}

int sentinel_is_quarantined(const char *node_uuid)
{
    if (!node_uuid) return 0;
    return find_entry(node_uuid) >= 0 ? 1 : 0;
}

int sentinel_quarantine_level(const char *node_uuid)
{
    if (!node_uuid) return 0;
    int idx = find_entry(node_uuid);
    if (idx < 0) return 0;
    return q_registry[idx].level;
}
