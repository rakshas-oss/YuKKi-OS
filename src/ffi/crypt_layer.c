#include "laminar_api.h"

#include <math.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static pthread_mutex_t crypt_state_lock = PTHREAD_MUTEX_INITIALIZER;
static double sigma_state = 10.0;
static double rho_state = 28.0;
static double beta_state = 8.33333333333;

static uint8_t rotl8(uint8_t value, unsigned int shift) {
    shift &= 7u;
    if (shift == 0u) {
        return value;
    }
    return (uint8_t)((value << shift) | (value >> (8u - shift)));
}

static uint8_t rotr8(uint8_t value, unsigned int shift) {
    shift &= 7u;
    if (shift == 0u) {
        return value;
    }
    return (uint8_t)((value >> shift) | (value << (8u - shift)));
}

static uint64_t mix64(uint64_t value) {
    value ^= value >> 33u;
    value *= 0xff51afd7ed558ccdULL;
    value ^= value >> 33u;
    value *= 0xc4ceb9fe1a85ec53ULL;
    value ^= value >> 33u;
    return value;
}

static uint64_t derive_seed(uint64_t nonce, size_t len) {
    uint64_t sigma_bits = (uint64_t)llround(fabs(sigma_state) * 1000000.0);
    uint64_t rho_bits = (uint64_t)llround(fabs(rho_state) * 1000000.0);
    uint64_t beta_bits = (uint64_t)llround(fabs(beta_state) * 1000000.0);

    return mix64(
        nonce ^
        (sigma_bits << 1u) ^
        (rho_bits << 21u) ^
        (beta_bits << 42u) ^
        ((uint64_t)len << 9u) ^
        0x9E3779B97F4A7C15ULL
    );
}

void crypt_layer_configure(double sigma, double rho, double beta) {
    pthread_mutex_lock(&crypt_state_lock);
    sigma_state = sigma;
    rho_state = rho;
    beta_state = beta;
    pthread_mutex_unlock(&crypt_state_lock);
}

static int crypt_layer_transform(
    const uint8_t* input,
    size_t len,
    uint64_t nonce,
    uint8_t* output,
    int encrypt
) {
    size_t index;
    uint64_t state;
    uint64_t stream;

    if ((!input && len != 0u) || !output) {
        return -1;
    }

    pthread_mutex_lock(&crypt_state_lock);
    state = derive_seed(nonce, len);
    stream = state;

    for (index = 0; index < len; ++index) {
        uint8_t pauli_mask;
        uint8_t phase;
        unsigned int rotation;
        uint8_t key;
        uint8_t value;

        stream ^= stream << 7u;
        stream ^= stream >> 9u;
        stream ^= stream << 8u;

        pauli_mask = (uint8_t)((state >> ((index % 8u) * 8u)) & 0xFFu);
        pauli_mask ^= (uint8_t)(0xA5u + (uint8_t)(index * 17u));
        phase = (uint8_t)(((stream >> 16u) & 0x0Fu) ^ ((index * 13u) & 0x0Fu));
        rotation = (unsigned int)((stream >> 8u) & 0x07u);
        key = (uint8_t)(stream & 0xFFu) ^ pauli_mask;

        if (encrypt) {
            value = (uint8_t)(input[index] ^ key ^ (uint8_t)index);
            value = (uint8_t)(value + phase);
            output[index] = rotl8(value, rotation);
        } else {
            value = rotr8(input[index], rotation);
            value = (uint8_t)(value - phase);
            output[index] = (uint8_t)(value ^ key ^ (uint8_t)index);
        }

        state = mix64(state + stream + (uint64_t)index + 0x517CC1B727220A95ULL);
    }

    pthread_mutex_unlock(&crypt_state_lock);
    return 0;
}

int crypt_layer_encrypt(const uint8_t* input, size_t len, uint64_t nonce, uint8_t* output) {
    return crypt_layer_transform(input, len, nonce, output, 1);
}

int crypt_layer_decrypt(const uint8_t* input, size_t len, uint64_t nonce, uint8_t* output) {
    return crypt_layer_transform(input, len, nonce, output, 0);
}

void crypt_layer_encrypt_block(const uint8_t* input, uint64_t nonce, uint8_t output[16]) {
    if (!output) {
        return;
    }
    if (!input) {
        memset(output, 0, 16);
        return;
    }
    if (crypt_layer_encrypt(input, 16u, nonce, output) != 0) {
        memset(output, 0, 16);
    }
}
