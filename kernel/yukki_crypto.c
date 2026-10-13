#include "yukki_crypto.h"
#include <string.h>

#ifdef USE_MBEDTLS
#include "mbedtls/md.h"
#include "mbedtls/aes.h"
#endif

/* If no crypto backend is provided, these functions return error codes. */
int yukki_protect_header(const uint8_t *net_key, const uint8_t *header, uint8_t header_len, uint8_t *mac_out) {
    if (!net_key || !header || !mac_out) return -1;

#ifdef USE_MBEDTLS
    /* Use HMAC-SHA256 and truncate to YUKKI_HEADER_MAC_LEN bytes */
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md_info) return -2;

    unsigned char full_mac[32];
    if (mbedtls_md_hmac(md_info, net_key, YUKKI_NETWORK_KEY_LEN, header, header_len, full_mac) != 0) return -3;
    memcpy(mac_out, full_mac, YUKKI_HEADER_MAC_LEN);
    /* Zeroize full_mac */
    memset(full_mac, 0, sizeof(full_mac));
    return 0;
#else
    /* No secure implementation compiled in. Caller must provide platform crypto. */
    (void)net_key; (void)header; (void)header_len; (void)mac_out;
    return -10; /* not implemented */
#endif
}

int yukki_verify_header(const uint8_t *net_key, const uint8_t *header, uint8_t header_len, const uint8_t *mac) {
    if (!net_key || !header || !mac) return -1;
#ifdef USE_MBEDTLS
    uint8_t expected[YUKKI_HEADER_MAC_LEN];
    int rc = yukki_protect_header(net_key, header, header_len, expected);
    if (rc != 0) return rc;
    /* constant-time compare */
    uint8_t diff = 0;
    for (uint8_t i = 0; i < YUKKI_HEADER_MAC_LEN; i++) diff |= (expected[i] ^ mac[i]);
    memset(expected, 0, sizeof(expected));
    return diff ? -4 : 0;
#else
    (void)net_key; (void)header; (void)header_len; (void)mac;
    return -10;
#endif
}
