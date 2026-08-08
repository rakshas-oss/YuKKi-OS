#include "laminar_api.h"
#include <math.h>
#include <string.h>

/* Legacy-Safe Quantum Slab Descriptor */
#pragma pack(push, 1)
typedef struct {
    uint32_t q_slab_handle;
    uint8_t  encrypted_signature[16];
    uint32_t active_basis;
} SecureQuantumSlab;
#pragma pack(pop)

static double x_state = 0.1;
static double y_state = 0.0;
static double z_state = 0.0;
static double sigma_param = 10.0;
static double rho_param = 28.0;
static double beta_param = 8.33333333333;

/* Hardcoded 256-bit (32-byte) Shared Mesh Key */
static const uint32_t CHACHA_KEY[8] = {
    0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
    0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c
};

/* Constant-Time ARX Macros for ChaCha20 */
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define QUARTERROUND(a, b, c, d) \
  a += b; d ^= a; d = ROTL32(d, 16); \
  c += d; b ^= c; b = ROTL32(b, 12); \
  a += b; d ^= a; d = ROTL32(d, 8);  \
  c += d; b ^= c; b = ROTL32(b, 7);

void chaos_engine_init(double sigma, double rho, double beta) {
    sigma_param = sigma; rho_param = rho; beta_param = beta;
    x_state = 0.1; y_state = 0.0; z_state = 0.0;
}

/* ChaCha20 Keystream Generator (Generates 64 bytes of secure keystream) */
void chacha20_block(uint32_t out[16], uint64_t nonce_seq) {
    uint32_t state[16];
    uint32_t working_state[16];
    
    // 1. Setup ChaCha20 Initial State Matrix
    // Constants ("expand 32-byte k")
    state[0] = 0x61707865; state[1] = 0x3320646e; 
    state[2] = 0x79622d32; state[3] = 0x6b206574;
    // 256-bit Key
    for (int i = 0; i < 8; i++) state[4 + i] = CHACHA_KEY[i];
    // Block Counter (0 for single block)
    state[12] = 0; 
    // 96-bit Nonce (Derived from Packet Sequence ID)
    state[13] = 0; 
    state[14] = (uint32_t)(nonce_seq & 0xFFFFFFFF);
    state[15] = (uint32_t)(nonce_seq >> 32);

    for (int i = 0; i < 16; i++) working_state[i] = state[i];

    // 2. Perform 20 Rounds (10 column rounds, 10 diagonal rounds)
    for (int i = 0; i < 10; i++) {
        QUARTERROUND(working_state[0], working_state[4], working_state[8],  working_state[12])
        QUARTERROUND(working_state[1], working_state[5], working_state[9],  working_state[13])
        QUARTERROUND(working_state[2], working_state[6], working_state[10], working_state[14])
        QUARTERROUND(working_state[3], working_state[7], working_state[11], working_state[15])
        QUARTERROUND(working_state[0], working_state[5], working_state[10], working_state[15])
        QUARTERROUND(working_state[1], working_state[6], working_state[11], working_state[12])
        QUARTERROUND(working_state[2], working_state[7], working_state[8],  working_state[13])
        QUARTERROUND(working_state[3], working_state[4], working_state[9],  working_state[14])
    }

    // 3. Add working state back to initial state
    for (int i = 0; i < 16; i++) out[i] = working_state[i] + state[i];
}

/* Encrypt 16-Byte Payload using ChaCha20 Keystream */
int secure_chacha20_bind(const uint8_t *raw_msg, size_t len, uint64_t seq_id, SecureQuantumSlab *out_slab) {
    if (!raw_msg || !out_slab) return -1;
    out_slab->q_slab_handle = 0xCC20A5A5;
    out_slab->active_basis = 0x1; 
    
    // Generate 64-byte keystream block based on the unique Sequence ID
    uint32_t keystream_block[16];
    chacha20_block(keystream_block, seq_id);
    
    // Cast the first 16 bytes of the keystream to XOR against our payload
    uint8_t *keystream_bytes = (uint8_t*)keystream_block;

    for (int i = 0; i < 16; i++) {
        out_slab->encrypted_signature[i] = (i < len) ? (raw_msg[i] ^ keystream_bytes[i]) : 0x00;
    }
    return 0;
}

void generate_lorenz_step(double dt) {
    double dx = sigma_param * (y_state - x_state);
    double dy = x_state * (rho_param - z_state) - y_state;
    double dz = x_state * y_state - beta_param * z_state;
    
    x_state += dx * dt; y_state += dy * dt; z_state += dz * dt;
    
    if (x_state != x_state || x_state > 1e308 || x_state < -1e308) x_state = 0.1;
    if (y_state != y_state || y_state > 1e308 || y_state < -1e308) y_state = 0.0;
    if (z_state != z_state || z_state > 1e308 || z_state < -1e308) z_state = 0.0;
}

void weave_spatiotemporal_frame(uint64_t seq, const uint8_t* payload_src, SpatiotemporalFrame* out_frame) {
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
        SecureQuantumSlab secure_slab;
        // Pass the seq_id as the cryptographic nonce
        secure_chacha20_bind(payload_src, 16, seq, &secure_slab);
        memcpy(out_frame->payload, secure_slab.encrypted_signature, 16); 
    }
}
