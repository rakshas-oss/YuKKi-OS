#ifndef YUKKI_CRYPTO_H
#define YUKKI_CRYPTO_H

#include <stdint.h>
#include <stdbool.h>

/* Header protection and authenticated header MAC for ADI frames.
 * This module provides an abstract API. By default it will use mbedTLS when
 * compiled with -DUSE_MBEDTLS. Otherwise, platform must provide implementations
 * or the functions will return an error. This avoids embedding custom crypto
 * primitives in the repo.
 */

#define YUKKI_HEADER_MAC_LEN 8U /* truncated MAC bytes placed in header */
#define YUKKI_NETWORK_KEY_LEN 16U /* AES-128 key size */

/* Protect header bytes in-place and append MAC_out (YUKKI_HEADER_MAC_LEN). */
int yukki_protect_header(const uint8_t *net_key, const uint8_t *header, uint8_t header_len, uint8_t *mac_out);

/* Verify header using net_key and provided mac (len YUKKI_HEADER_MAC_LEN). Returns 0 on success */
int yukki_verify_header(const uint8_t *net_key, const uint8_t *header, uint8_t header_len, const uint8_t *mac);

#endif
