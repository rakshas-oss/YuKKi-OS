#ifndef YUKKI_MESH_H
#define YUKKI_MESH_H

#include <stdint.h>
#include <stdbool.h>

#define YUKKI_MESH_MAX_LOCAL_NEIGHBORS 16U
#define YUKKI_MESH_MAX_HOPS 16U
#define YUKKI_MESH_NEIGHBOR_TTL_MS 3000U
#define YUKKI_MESH_Q16_16_SCALE 65536

typedef uint32_t yukki_node_id_t;

typedef struct {
    uint16_t magic;
    yukki_node_id_t src_id;
    yukki_node_id_t dst_id;
    int32_t dest_x_q16;
    int32_t dest_y_q16;
    int32_t dest_z_q16;
    uint8_t hop_count;
    uint8_t reserved;
} __attribute__((packed)) yukki_adi_header_t;

typedef struct {
    yukki_node_id_t node_id;
    int32_t x_q16;
    int32_t y_q16;
    int32_t z_q16;
    uint16_t quality;
    uint8_t battery_pct;
    uint8_t queue_load_pct;
    bool active;
    uint32_t last_seen_ms;
} yukki_neighbor_cache_entry_t;

typedef struct {
    yukki_node_id_t self_id;
    int32_t x_q16;
    int32_t y_q16;
    int32_t z_q16;
    yukki_neighbor_cache_entry_t neighbors[YUKKI_MESH_MAX_LOCAL_NEIGHBORS];
    uint8_t neighbor_count;
    uint32_t tick_ms;
} yukki_node_context_t;

typedef enum {
    YUKKI_ROUTE_SUCCESS = 0,
    YUKKI_ROUTE_DEAD_END,
    YUKKI_ROUTE_MAX_HOPS,
    YUKKI_ROUTE_INVALID
} yukki_route_status_t;

static inline int32_t yukki_float_to_q16(float v) {
    return (int32_t)(v * (float)YUKKI_MESH_Q16_16_SCALE);
}

static inline float yukki_q16_to_float(int32_t q) {
    return ((float)q) / (float)YUKKI_MESH_Q16_16_SCALE;
}

uint16_t yukki_compute_quality_from_etx_snr_q16(int32_t etx_q16, int32_t snr_db_q16);
void yukki_prune_stale_neighbors(yukki_node_context_t *ctx, uint32_t now_ms);
bool yukki_neighbor_cache_insert(yukki_node_context_t *ctx, const yukki_neighbor_cache_entry_t *entry);
yukki_route_status_t yukki_route_adi_frame(yukki_node_context_t *ctx,
                                          yukki_adi_header_t *hdr,
                                          const char *payload,
                                          uint32_t now_ms,
                                          yukki_node_id_t *chosen_next_hop_id);

#endif
