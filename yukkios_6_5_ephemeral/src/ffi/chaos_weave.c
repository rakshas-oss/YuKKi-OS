/* chaos_weave.c — YuKKi OS 6.5.0 Ephemeral Mesh Edition
 * C99 compatible. Links into the Rust binary via build.rs / cc crate.
 */

#include "laminar_api.h"
#include <math.h>
#include <string.h>
#include <stdlib.h>

/* ---------------------------------------------------------------------------
 * Lorenz state
 * --------------------------------------------------------------------------- */
static double x_state     = 0.1;
static double y_state     = 0.0;
static double z_state     = 0.0;
static double sigma_param = 10.0;
static double rho_param   = 28.0;
static double beta_param  = 8.33333333333;

void chaos_engine_init(double sigma, double rho, double beta) {
    sigma_param = sigma; rho_param = rho; beta_param = beta;
    x_state = 0.1; y_state = 0.0; z_state = 0.0;
}

void chaos_engine_reseed(double sigma, double rho, double beta,
                         double x0, double y0, double z0) {
    sigma_param = sigma; rho_param = rho; beta_param = beta;
    x_state = x0; y_state = y0; z_state = z0;
}

void generate_lorenz_step(double dt) {
    double dx = sigma_param * (y_state - x_state);
    double dy = x_state * (rho_param - z_state) - y_state;
    double dz = x_state * y_state - beta_param * z_state;
    x_state += dx * dt;
    y_state += dy * dt;
    z_state += dz * dt;
    /* Guard against NaN / overflow */
    if (x_state != x_state || x_state >  1e308 || x_state < -1e308) x_state = 0.1;
    if (y_state != y_state || y_state >  1e308 || y_state < -1e308) y_state = 0.0;
    if (z_state != z_state || z_state >  1e308 || z_state < -1e308) z_state = 0.0;
}

/* ---------------------------------------------------------------------------
 * Pauli binding shim (information-theoretic, not cryptographic)
 * --------------------------------------------------------------------------- */
#pragma pack(push, 1)
typedef struct {
    uint32_t q_slab_handle;
    uint8_t  pauli_signature[16];
    uint32_t active_basis;
} UncloneableQuantumSlab;
#pragma pack(pop)

static int unclonable_clifford_bind(const uint8_t *raw_msg, size_t len,
                                    UncloneableQuantumSlab *out_slab) {
    int i;
    if (!raw_msg || !out_slab) return -1;
    out_slab->q_slab_handle = 0xAE509001U;
    out_slab->active_basis  = 0x3U;
    for (i = 0; i < 16; i++) {
        out_slab->pauli_signature[i] =
            (i < (int)len) ? (uint8_t)(raw_msg[i] ^ 0xA5U) : 0x00U;
    }
    return 0;
}

void weave_spatiotemporal_frame(uint64_t seq, const uint8_t *payload_src,
                                SpatiotemporalFrame *out_frame) {
    double speed;
    if (payload_src) {
        sigma_param = 10.0 + (payload_src[0] / 255.0);
        rho_param   = 28.0 + (payload_src[1] / 255.0);
        beta_param  =  8.0 + (payload_src[2] / 255.0);
    }
    generate_lorenz_step(0.005);

    out_frame->seq_id     = seq;
    out_frame->x          = x_state;
    out_frame->y          = y_state;
    out_frame->z          = z_state;
    out_frame->u          = x_state * 0.125;
    out_frame->v          = y_state * 0.25;
    out_frame->w          = z_state * 0.5;
    speed = sqrt(x_state * x_state + y_state * y_state + z_state * z_state);
    out_frame->fluidity   = (float)(1.0 / (1.0 + exp(-speed / 10.0)));
    out_frame->drag       = 1.0f - out_frame->fluidity;
    out_frame->divergence = 0.0;

    memset(out_frame->payload, 0, 16);
    if (payload_src) {
        UncloneableQuantumSlab slab;
        unclonable_clifford_bind(payload_src, 16, &slab);
        memcpy(out_frame->payload, slab.pauli_signature, 16);
    }
}

/* ---------------------------------------------------------------------------
 * OOB Integrity — FNV-1a rolling hash, 60-frame sync, quarantine
 * --------------------------------------------------------------------------- */

#define FNV_OFFSET_BASIS_64 14695981039346656037ULL
#define FNV_PRIME_64        1099511628211ULL

static uint64_t oob_rolling_state = FNV_OFFSET_BASIS_64;

uint64_t oob_fnv1a_rolling_hash(uint64_t seed, const uint8_t *data, uint32_t len) {
    uint64_t hash = seed;
    uint32_t i;
    for (i = 0; i < len; i++) {
        hash ^= (uint64_t)data[i];
        hash *= FNV_PRIME_64;
    }
    return hash;
}

void oob_integrity_update(uint64_t seq, const uint8_t *payload, uint32_t len) {
    uint8_t seq_bytes[8];
    uint32_t i;
    for (i = 0; i < 8; i++) {
        seq_bytes[i] = (uint8_t)((seq >> (i * 8)) & 0xFF);
    }
    oob_rolling_state = oob_fnv1a_rolling_hash(oob_rolling_state, seq_bytes, 8);
    oob_rolling_state = oob_fnv1a_rolling_hash(oob_rolling_state, payload, len);
}

int oob_sync_check(uint64_t seq) {
    return (seq > 0 && (seq % 60) == 0) ? 1 : 0;
}

/* Simple in-process quarantine list — max 256 entries for this shim. */
#define MAX_QUARANTINE 256
#define UUID_MAX_LEN   64

static char quarantine_list[MAX_QUARANTINE][UUID_MAX_LEN];
static int  quarantine_count = 0;

void oob_quarantine_node(const char *node_uuid) {
    int i;
    if (!node_uuid || quarantine_count >= MAX_QUARANTINE) return;
    for (i = 0; i < quarantine_count; i++) {
        if (strncmp(quarantine_list[i], node_uuid, UUID_MAX_LEN - 1) == 0) return;
    }
    strncpy(quarantine_list[quarantine_count], node_uuid, UUID_MAX_LEN - 1);
    quarantine_list[quarantine_count][UUID_MAX_LEN - 1] = '\0';
    quarantine_count++;
}

int oob_is_quarantined(const char *node_uuid) {
    int i;
    if (!node_uuid) return 0;
    for (i = 0; i < quarantine_count; i++) {
        if (strncmp(quarantine_list[i], node_uuid, UUID_MAX_LEN - 1) == 0) return 1;
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * Ephemeral session-key derivation — v6.5.0
 * Mixes the caller-supplied 32-byte X25519 shared secret with the current
 * Lorenz state via FNV-1a to produce a 32-byte session key.
 * NOTE: This is a lightweight KDF shim; replace with HKDF for production use.
 * --------------------------------------------------------------------------- */
void ephemeral_derive_session_key(const uint8_t *shared_secret_32,
                                  uint8_t *out_key_32) {
    /* Encode current Lorenz state into 24 bytes (3 × f64 little-endian). */
    uint8_t lorenz_bytes[24];
    uint64_t xi, yi, zi;
    int i;

    memcpy(&xi, &x_state, 8);
    memcpy(&yi, &y_state, 8);
    memcpy(&zi, &z_state, 8);

    for (i = 0; i < 8; i++) {
        lorenz_bytes[i]      = (uint8_t)((xi >> (i * 8)) & 0xFF);
        lorenz_bytes[8 + i]  = (uint8_t)((yi >> (i * 8)) & 0xFF);
        lorenz_bytes[16 + i] = (uint8_t)((zi >> (i * 8)) & 0xFF);
    }

    /* Two-pass FNV-1a over shared_secret || lorenz_bytes, written into
     * out_key_32 as two consecutive 16-byte halves. */
    {
        uint64_t h = oob_fnv1a_rolling_hash(FNV_OFFSET_BASIS_64,
                                            shared_secret_32, 32);
        h = oob_fnv1a_rolling_hash(h, lorenz_bytes, 24);
        for (i = 0; i < 8; i++) out_key_32[i] = (uint8_t)((h >> (i * 8)) & 0xFF);
    }
    {
        uint64_t h = oob_fnv1a_rolling_hash(FNV_OFFSET_BASIS_64 ^ 0xDEADBEEFCAFEBABEULL,
                                            shared_secret_32, 32);
        h = oob_fnv1a_rolling_hash(h, lorenz_bytes, 24);
        for (i = 0; i < 8; i++) out_key_32[8 + i] = (uint8_t)((h >> (i * 8)) & 0xFF);
    }
    {
        uint64_t h = oob_fnv1a_rolling_hash(FNV_OFFSET_BASIS_64 ^ 0xFEEDFACEDEAD0001ULL,
                                            lorenz_bytes, 24);
        h = oob_fnv1a_rolling_hash(h, shared_secret_32, 32);
        for (i = 0; i < 8; i++) out_key_32[16 + i] = (uint8_t)((h >> (i * 8)) & 0xFF);
    }
    {
        uint64_t h = oob_fnv1a_rolling_hash(FNV_OFFSET_BASIS_64 ^ 0xCAFEBABE00112233ULL,
                                            lorenz_bytes, 24);
        h = oob_fnv1a_rolling_hash(h, shared_secret_32, 32);
        for (i = 0; i < 8; i++) out_key_32[24 + i] = (uint8_t)((h >> (i * 8)) & 0xFF);
    }
}
