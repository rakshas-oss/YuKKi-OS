#include "yukki_mesh.h"

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

/* Optional debug; remove or guard in production builds */
#ifdef YUKKI_MESH_DEBUG
#include <stdio.h>
#endif

#define YUKKI_MESH_MIN_ETX_Q16 65536 /* 1.0 in Q16.16 */
#define YUKKI_MESH_QUALITY_MAX 65535U

static inline uint32_t yukki_clamp_u32(uint32_t v, uint32_t lo, uint32_t hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

uint16_t yukki_compute_quality_from_etx_snr_q16(int32_t etx_q16, int32_t snr_db_q16) {
    if (etx_q16 <= 0) etx_q16 = (int32_t)YUKKI_MESH_MIN_ETX_Q16;

    /* Use 64-bit intermediate for precision and to avoid overflow */
    int64_t numer = (int64_t)snr_db_q16 * (int64_t)YUKKI_MESH_Q16_16_SCALE;
    int64_t denom = (int64_t)etx_q16;
    int64_t quality_q16 = numer / denom;

    if (quality_q16 <= 0) return 0;

    uint32_t q = (uint32_t)(quality_q16 >> 16);
    return (uint16_t)yukki_clamp_u32(q, 0U, YUKKI_MESH_QUALITY_MAX);
}

void yukki_prune_stale_neighbors(yukki_node_context_t *ctx, uint32_t now_ms) {
    if (!ctx) return;

    for (int i = 0; i < ctx->neighbor_count; ) {
        yukki_neighbor_cache_entry_t *n = &ctx->neighbors[i];
        if (!n->active || (now_ms - n->last_seen_ms) > YUKKI_MESH_NEIGHBOR_TTL_MS) {
            ctx->neighbors[i] = ctx->neighbors[ctx->neighbor_count - 1];
            ctx->neighbor_count--;
        } else {
            i++;
        }
    }
}

bool yukki_neighbor_cache_insert(yukki_node_context_t *ctx, const yukki_neighbor_cache_entry_t *entry) {
    if (!ctx || !entry) return false;

    for (int i = 0; i < ctx->neighbor_count; i++) {
        if (ctx->neighbors[i].node_id == entry->node_id) {
            ctx->neighbors[i] = *entry;
            return true;
        }
    }

    if (ctx->neighbor_count < YUKKI_MESH_MAX_LOCAL_NEIGHBORS) {
        ctx->neighbors[ctx->neighbor_count++] = *entry;
        return true;
    }

    uint32_t oldest_idx = 0;
    uint32_t oldest_ts = UINT32_MAX;
    for (int i = 0; i < ctx->neighbor_count; i++) {
        if (ctx->neighbors[i].last_seen_ms < oldest_ts) {
            oldest_ts = ctx->neighbors[i].last_seen_ms;
            oldest_idx = i;
        }
    }
    ctx->neighbors[oldest_idx] = *entry;
    return true;
}

static uint64_t yukki_compute_score_fp_q32(const yukki_neighbor_cache_entry_t *n,
                                           int32_t target_x_q16,
                                           int32_t target_y_q16,
                                           int32_t target_z_q16) {
    int64_t dx = (int64_t)n->x_q16 - (int64_t)target_x_q16;
    int64_t dy = (int64_t)n->y_q16 - (int64_t)target_y_q16;
    int64_t dz = (int64_t)n->z_q16 - (int64_t)target_z_q16;

    uint64_t dist_sq_q32 = (uint64_t)(dx * dx + dy * dy + dz * dz);
    uint64_t denom = dist_sq_q32 + 1ULL;
    uint64_t numer = ((uint64_t)n->quality) << 32;
    return numer / denom;
}

yukki_route_status_t yukki_route_adi_frame(yukki_node_context_t *ctx,
                                          yukki_adi_header_t *hdr,
                                          const char *payload,
                                          uint32_t now_ms,
                                          yukki_node_id_t *chosen_next_hop_id) {
    (void)payload;

    if (!ctx || !hdr || !chosen_next_hop_id) return YUKKI_ROUTE_INVALID;

    yukki_prune_stale_neighbors(ctx, now_ms);

    if (hdr->hop_count >= YUKKI_MESH_MAX_HOPS) {
        return YUKKI_ROUTE_MAX_HOPS;
    }

    if (ctx->neighbor_count == 0) {
        return YUKKI_ROUTE_DEAD_END;
    }

    uint64_t best_score = 0;
    int best_idx = -1;

    for (int i = 0; i < ctx->neighbor_count; i++) {
        yukki_neighbor_cache_entry_t *n = &ctx->neighbors[i];
        if (!n->active) continue;

        uint64_t score = yukki_compute_score_fp_q32(n,
                                                   hdr->dest_x_q16,
                                                   hdr->dest_y_q16,
                                                   hdr->dest_z_q16);
        if (score > best_score) {
            best_score = score;
            best_idx = i;
        }
    }

    if (best_idx < 0) {
        return YUKKI_ROUTE_DEAD_END;
    }

    *chosen_next_hop_id = ctx->neighbors[best_idx].node_id;
    hdr->hop_count++;
    return YUKKI_ROUTE_SUCCESS;
}
