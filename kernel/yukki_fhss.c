#include "yukki_fhss.h"
#include <string.h>

/* Small Fibonacci LFSR for pseudo-random sequence (16-bit) */
static inline uint16_t yukki_lfsr_next(uint16_t s) {
    /* taps: 16,14,13,11 (x^16 + x^14 + x^13 + x^11 + 1) */
    uint16_t bit = ((s >> 0) ^ (s >> 2) ^ (s >> 3) ^ (s >> 5)) & 1U;
    return (s >> 1) | (bit << 15);
}

void yukki_fhss_init(yukki_fhss_ctx_t *ctx, const uint16_t *channels, uint8_t channel_count, uint32_t dwell_ms, uint16_t seed) {
    if (!ctx) return;
    memset(ctx, 0, sizeof(*ctx));
    if (channel_count > YUKKI_FHSS_MAX_CHANNELS) channel_count = YUKKI_FHSS_MAX_CHANNELS;
    for (int i = 0; i < channel_count; i++) ctx->channels[i] = channels[i];
    ctx->channel_count = channel_count;
    ctx->dwell_ms = dwell_ms;
    ctx->last_hop_ms = 0;
    ctx->lfsr_state = seed ? seed : 0xACE1u; /* default seed */
    ctx->index = 0;
}

uint16_t yukki_fhss_get_current_channel(const yukki_fhss_ctx_t *ctx) {
    if (!ctx || ctx->channel_count == 0) return 0;
    return ctx->channels[ctx->index % ctx->channel_count];
}

uint16_t yukki_fhss_update_and_get_next_channel(yukki_fhss_ctx_t *ctx, uint32_t now_ms) {
    if (!ctx || ctx->channel_count == 0) return 0;
    if ((now_ms - ctx->last_hop_ms) < ctx->dwell_ms) return yukki_fhss_get_current_channel(ctx);

    /* advance LFSR and compute next pseudo-index */
    ctx->lfsr_state = yukki_lfsr_next(ctx->lfsr_state);
    ctx->index = (uint8_t)(ctx->lfsr_state % ctx->channel_count);
    ctx->last_hop_ms = now_ms;
    return yukki_fhss_get_current_channel(ctx);
}

void yukki_fhss_sync(yukki_fhss_ctx_t *ctx, uint16_t remote_lfsr_state, uint8_t remote_index) {
    if (!ctx) return;
    /* simple resync: adopt remote state and index (requires trust) */
    ctx->lfsr_state = remote_lfsr_state;
    ctx->index = remote_index % ctx->channel_count;
}
