#include "yukki_emcon.h"
#include <string.h>

void yukki_emcon_init(yukki_emcon_ctx_t *ctx, uint32_t now_ms) {
    if (!ctx) return;
    memset(ctx, 0, sizeof(*ctx));
    ctx->policy = YUKKI_EMCON_NORMAL;
    ctx->last_emit_ms = now_ms;
    ctx->min_silence_ms = 100; /* default 100ms between bursts */
    ctx->heartbeat_period_ms = 1000; /* allow heartbeat once per second */
}

void yukki_emcon_set_policy(yukki_emcon_ctx_t *ctx, yukki_emcon_policy_t p) {
    if (!ctx) return;
    ctx->policy = p;
    /* tune silence for stricter policies */
    switch (p) {
        case YUKKI_EMCON_NORMAL:
            ctx->min_silence_ms = 20;
            ctx->heartbeat_period_ms = 1000;
            break;
        case YUKKI_EMCON_REDUCED:
            ctx->min_silence_ms = 200;
            ctx->heartbeat_period_ms = 2000;
            break;
        case YUKKI_EMCON_STRICT:
            ctx->min_silence_ms = 1000;
            ctx->heartbeat_period_ms = 5000;
            break;
    }
}

bool yukki_emcon_can_transmit(yukki_emcon_ctx_t *ctx,
                              uint32_t now_ms,
                              yukki_emcon_reason_t reason,
                              const yukki_adi_header_t *hdr,
                              const yukki_node_context_t *node_ctx) {
    (void)hdr;
    (void)node_ctx;
    if (!ctx) return false;

    /* Always allow when policy is normal */
    if (ctx->policy == YUKKI_EMCON_NORMAL) return true;

    /* Allow heartbeat occasionally even in strict modes */
    if (reason == YUKKI_EMCON_REASON_HEARTBEAT) {
        if ((now_ms - ctx->last_emit_ms) >= ctx->heartbeat_period_ms) return true;
        return false;
    }

    /* In strict mode, only allow explicit control/safety */
    if (ctx->policy == YUKKI_EMCON_STRICT) {
        if (reason == YUKKI_EMCON_REASON_CTRL || reason == YUKKI_EMCON_REASON_SAFETY) {
            /* enforce minimum silence between bursts */
            if ((now_ms - ctx->last_emit_ms) >= ctx->min_silence_ms) return true;
        }
        return false;
    }

    /* Reduced mode: allow transmissions but enforce longer silence */
    if (ctx->policy == YUKKI_EMCON_REDUCED) {
        if ((now_ms - ctx->last_emit_ms) >= ctx->min_silence_ms) return true;
        /* allow control/safety always (but still respect silence window to avoid bursts) */
        if (reason == YUKKI_EMCON_REASON_SAFETY && (now_ms - ctx->last_emit_ms) >= (ctx->min_silence_ms / 2)) return true;
        return false;
    }

    return false;
}

void yukki_emcon_record_transmit(yukki_emcon_ctx_t *ctx, uint32_t now_ms) {
    if (!ctx) return;
    ctx->last_emit_ms = now_ms;
}
