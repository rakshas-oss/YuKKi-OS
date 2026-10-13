#ifndef YUKKI_EMCON_H
#define YUKKI_EMCON_H

#include <stdint.h>
#include <stdbool.h>
#include "yukki_mesh.h"

/* EMCON (Emission Control) policies for conserving RF emissions */

typedef enum {
    YUKKI_EMCON_NORMAL = 0, /* normal operation: transmit freely */
    YUKKI_EMCON_REDUCED,    /* reduced emissions: prefer silence, short TX bursts */
    YUKKI_EMCON_STRICT      /* strict EMCON: only critical control, minimize emissions */
} yukki_emcon_policy_t;

/* Reasons a frame may be considered critical and allowed under strict EMCON */
typedef enum {
    YUKKI_EMCON_REASON_NONE = 0,
    YUKKI_EMCON_REASON_CTRL,     /* explicit control command */
    YUKKI_EMCON_REASON_SAFETY,   /* safety-critical (collision avoidance) */
    YUKKI_EMCON_REASON_HEARTBEAT /* heartbeat allowed periodically */
} yukki_emcon_reason_t;

typedef struct {
    yukki_emcon_policy_t policy;
    uint32_t last_emit_ms;      /* monotonic time of last transmit */
    uint32_t min_silence_ms;    /* enforced silence interval in reduced/strict modes */
    uint32_t heartbeat_period_ms; /* allow heartbeat even in strict modes */
} yukki_emcon_ctx_t;

/* Initialize EMCON context with reasonable defaults */
void yukki_emcon_init(yukki_emcon_ctx_t *ctx, uint32_t now_ms);

/* Set EMCON policy */
void yukki_emcon_set_policy(yukki_emcon_ctx_t *ctx, yukki_emcon_policy_t p);

/* Called when node intends to transmit; returns true if transmit allowed */
bool yukki_emcon_can_transmit(yukki_emcon_ctx_t *ctx,
                              uint32_t now_ms,
                              yukki_emcon_reason_t reason,
                              const yukki_adi_header_t *hdr,
                              const yukki_node_context_t *node_ctx);

/* Inform EMCON that a transmit occurred (updates last_emit_ms) */
void yukki_emcon_record_transmit(yukki_emcon_ctx_t *ctx, uint32_t now_ms);

#endif
