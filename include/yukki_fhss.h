#ifndef YUKKI_FHSS_H
#define YUKKI_FHSS_H

#include <stdint.h>
#include <stdbool.h>

/* Simple FHSS controller: maintains hop schedule and generates next channel
 * using a lightweight LFSR PRNG seeded per-network.
 */

#define YUKKI_FHSS_MAX_CHANNELS 32

typedef struct {
    uint16_t channels[YUKKI_FHSS_MAX_CHANNELS]; /* channel identifiers (e.g., frequency indices) */
    uint8_t channel_count;
    uint32_t dwell_ms;    /* how long to stay on each channel */
    uint32_t last_hop_ms; /* last hop time */
    uint16_t lfsr_state;  /* PRNG state */
    uint8_t index;        /* current index in pseudo-shuffled schedule */
} yukki_fhss_ctx_t;

void yukki_fhss_init(yukki_fhss_ctx_t *ctx, const uint16_t *channels, uint8_t channel_count, uint32_t dwell_ms, uint16_t seed);
uint16_t yukki_fhss_get_current_channel(const yukki_fhss_ctx_t *ctx);
uint16_t yukki_fhss_update_and_get_next_channel(yukki_fhss_ctx_t *ctx, uint32_t now_ms);

/* Optional: receive a sync beacon containing a network hop counter to resync */
void yukki_fhss_sync(yukki_fhss_ctx_t *ctx, uint16_t remote_lfsr_state, uint8_t remote_index);

#endif
