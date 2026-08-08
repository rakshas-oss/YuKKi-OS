#include "laminar_api.h"
#include <string.h>
#include <math.h>

static double x_state = 0.1;
static double y_state = 0.0;
static double z_state = 0.0;
static double sigma_param = 10.0;
static double rho_param = 28.0;
static double beta_param = 8.33333333333;

void chaos_engine_init(double sigma, double rho, double beta) {
    sigma_param = sigma; rho_param = rho; beta_param = beta;
    x_state = 0.1; y_state = 0.0; z_state = 0.0;
}

void generate_lorenz_step(double dt) {
    double dx = sigma_param * (y_state - x_state);
    double dy = x_state * (rho_param - z_state) - y_state;
    double dz = x_state * y_state - beta_param * z_state;
    
    x_state += dx * dt; y_state += dy * dt; z_state += dz * dt;
    
    /* Legacy fallback for math macros */
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
        crypt_layer_encrypt_block(payload_src, seq, out_frame->payload);
    }
}
