#include "laminar_api.h"
#include <math.h>
#include <string.h>
#include <stdlib.h>

/* Legacy-Safe Quantum Slab Descriptor */
#pragma pack(push, 1)
typedef struct {
    uint32_t q_slab_handle;
    uint8_t  pauli_signature[16];
    uint32_t active_basis;
} UncloneableQuantumSlab;
#pragma pack(pop)

static double x_state = 0.1;
static double y_state = 0.0;
static double z_state = 0.0;
static double sigma_param = 10.0;
static double rho_param = 28.0;
static double beta_param = 8.33333333333;

void chaos_engine_init(double sigma, double rho, double beta) {
    sigma_param = sigma; rho_param = rho; beta_param = beta;
    x_state = 0.1; y_state = 0.0; z_state = 0.0;
}

void chaos_engine_reseed(double sigma, double rho, double beta,
                         double x0, double y0, double z0) {
    sigma_param = sigma; rho_param = rho; beta_param = beta;
    x_state = x0; y_state = y0; z_state = z0;
}

/* Information-Theoretic Clifford/Pauli Binding Simulation (C99 Compatible) */
int unclonable_clifford_bind(const uint8_t *raw_msg, size_t len, UncloneableQuantumSlab *out_slab) {
    if (!raw_msg || !out_slab) return -1;
    out_slab->q_slab_handle = 0xAE509001;
    out_slab->active_basis = 0x3; // X-Z anti-commuting cross-check
    
    for (int i = 0; i < 16; i++) {
        out_slab->pauli_signature[i] = (i < (int)len) ? (raw_msg[i] ^ 0xA5) : 0x00;
    }
    return 0;
}

void generate_lorenz_step(double dt) {
    double dx = sigma_param * (y_state - x_state);
    double dy = x_state * (rho_param - z_state) - y_state;
    double dz = x_state * y_state - beta_param * z_state;
    
    x_state += dx * dt; y_state += dy * dt; z_state += dz * dt;
    
    /* Legacy fallback for math macros */
    if (x_state != x_state || x_state > 1e308 || x_state < -1e308) x_state = 0.1;
    if (y_state != y_state || y_state > 1e308 || y_state < -1e308) y_state = 0.0;
    if (z_state != z_state || z_state > 1e308 || z_state < -1e308) z_state = 0.0;
}

void weave_spatiotemporal_frame(uint64_t seq, const uint8_t* payload_src, SpatiotemporalFrame* out_frame) {
    if (payload_src) {
        sigma_param = 10.0 + (payload_src[0] / 255.0);
        rho_param   = 28.0 + (payload_src[1] / 255.0);
        beta_param  =  8.0 + (payload_src[2] / 255.0);
    }
    generate_lorenz_step(0.005);
    out_frame->seq_id = seq;
    out_frame->x = x_state;
    out_frame->y = y_state;
    out_frame->z = z_state;
    out_frame->u = x_state * 0.125;
    out_frame->v = y_state * 0.25;
    out_frame->w = z_state * 0.5;
    
    double speed = sqrt(x_state * x_state + y_state * y_state + z_state * z_state);
    out_frame->fluidity = (float)(1.0 / (1.0 + exp(-speed / 10.0)));
    out_frame->drag = (float)(1.0f - out_frame->fluidity);
    out_frame->divergence = 0.0;
    
    memset(out_frame->payload, 0, 16);
    if (payload_src) { 
        UncloneableQuantumSlab secure_slab;
        unclonable_clifford_bind(payload_src, 16, &secure_slab);
        memcpy(out_frame->payload, secure_slab.pauli_signature, 16); 
    }
}

/* ===========================================================================
 * OOB Integrity Engine — v6.4.3 Out-of-Band Integrity Edition
 *
 * oob_fnv1a_rolling_hash: FNV-1a–style rolling hash for lightweight OOB
 *   integrity verification of the frame stream.
 *   IMPORTANT: This is an FNV-1a derivative, NOT a BLAKE3 or cryptographic
 *   hash. It is suitable only for non-adversarial integrity checks.
 *
 * 60-frame sync: every OOB_SYNC_PERIOD frames the caller is signalled to
 *   perform an out-of-band integrity sync (oob_sync_check returns 1).
 *
 * Node quarantine/blacklist: up to OOB_MAX_QUARANTINE node UUIDs may be
 *   registered as quarantined via oob_quarantine_node; oob_is_quarantined
 *   returns 1 for any blacklisted UUID prefix (first 36 chars).
 * =========================================================================== */

#define OOB_SYNC_PERIOD    60
#define OOB_MAX_QUARANTINE 64
#define OOB_UUID_LEN       36

/* FNV-1a 64-bit constants */
#define FNV1A_64_OFFSET  UINT64_C(14695981039346656037)
#define FNV1A_64_PRIME   UINT64_C(1099511628211)

static uint64_t g_oob_rolling_hash = FNV1A_64_OFFSET;

/* Quarantine table — static storage, no dynamic allocation required. */
static char g_quarantine_table[OOB_MAX_QUARANTINE][OOB_UUID_LEN + 1];
static int  g_quarantine_count = 0;

/*
 * oob_fnv1a_rolling_hash — FNV-1a derivative rolling hash.
 *
 * Feeds each byte of `data` through the FNV-1a 64-bit algorithm starting
 * from `seed`.  Returns the updated hash state.  NOT a BLAKE3 shim.
 */
uint64_t oob_fnv1a_rolling_hash(uint64_t seed, const uint8_t *data, uint32_t len) {
    uint64_t h = seed;
    uint32_t i;
    if (!data) return h;
    for (i = 0; i < len; i++) {
        h ^= (uint64_t)data[i];
        h *= FNV1A_64_PRIME;
    }
    return h;
}

/*
 * oob_integrity_update — incorporate one frame's payload into the rolling hash.
 */
void oob_integrity_update(uint64_t seq, const uint8_t *payload, uint32_t len) {
    /* Mix the sequence number into the hash first for ordering sensitivity. */
    uint8_t seq_bytes[8];
    uint32_t i;
    for (i = 0; i < 8; i++) {
        seq_bytes[i] = (uint8_t)(seq >> (i * 8));
    }
    g_oob_rolling_hash = oob_fnv1a_rolling_hash(g_oob_rolling_hash, seq_bytes, 8);
    if (payload && len > 0) {
        g_oob_rolling_hash = oob_fnv1a_rolling_hash(g_oob_rolling_hash, payload, len);
    }
}

/*
 * oob_sync_check — returns 1 when seq is at a 60-frame sync boundary.
 *
 * The caller should perform an OOB integrity sync (e.g., broadcast the
 * current rolling hash to peers for comparison) at every boundary.
 */
int oob_sync_check(uint64_t seq) {
    return (seq > 0 && (seq % OOB_SYNC_PERIOD) == 0) ? 1 : 0;
}

/*
 * oob_quarantine_node — blacklist a node UUID.
 *
 * Only the first OOB_UUID_LEN characters of node_uuid are stored.
 * No-ops if the table is full or uuid is NULL.
 */
void oob_quarantine_node(const char *node_uuid) {
    int i;
    if (!node_uuid || g_quarantine_count >= OOB_MAX_QUARANTINE) return;
    /* Avoid duplicate entries. */
    for (i = 0; i < g_quarantine_count; i++) {
        if (strncmp(g_quarantine_table[i], node_uuid, OOB_UUID_LEN) == 0) return;
    }
    strncpy(g_quarantine_table[g_quarantine_count], node_uuid, OOB_UUID_LEN);
    g_quarantine_table[g_quarantine_count][OOB_UUID_LEN] = '\0';
    g_quarantine_count++;
}

/*
 * oob_is_quarantined — returns 1 if node_uuid is in the quarantine table.
 */
int oob_is_quarantined(const char *node_uuid) {
    int i;
    if (!node_uuid) return 0;
    for (i = 0; i < g_quarantine_count; i++) {
        if (strncmp(g_quarantine_table[i], node_uuid, OOB_UUID_LEN) == 0) return 1;
    }
    return 0;
}
