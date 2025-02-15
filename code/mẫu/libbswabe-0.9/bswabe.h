#ifndef BSWABE_H
#define BSWABE_H

#include <relic/relic.h>
#include <glib.h>

#if defined (__cplusplus)
extern "C" {
#endif

/* Public Key */
typedef struct {
    g1_t g;            // G1 generator
    g2_t gp;           // G2 generator
    gt_t g_hat_alpha;  // Pairing result e(g, gp)^alpha
    g1_t h;            // Extra element for encryption
} bswabe_pub_t;

/* Master Secret Key */
typedef struct {
    g2_t g_alpha; // g_alpha = gp^alpha
    bn_t beta;    // Master secret beta
} bswabe_msk_t;

typedef struct bswabe_prv_s bswabe_prv_t;
typedef struct bswabe_cph_s bswabe_cph_t;

/* API Functions */
void bswabe_setup(bswabe_pub_t** pub, bswabe_msk_t** msk);
bswabe_prv_t* bswabe_keygen(bswabe_pub_t* pub, bswabe_msk_t* msk, char** attributes);
bswabe_cph_t* bswabe_enc(bswabe_pub_t* pub, gt_t m, char* policy);
int bswabe_dec(bswabe_pub_t* pub, bswabe_prv_t* prv, bswabe_cph_t* cph, gt_t m);

void bswabe_pub_free(bswabe_pub_t* pub);
void bswabe_msk_free(bswabe_msk_t* msk);
void bswabe_prv_free(bswabe_prv_t* prv);
void bswabe_cph_free(bswabe_cph_t* cph);

char* bswabe_error();

/* Serialization */
bswabe_pub_t* bswabe_pub_unserialize(GByteArray* buf, int free);
GByteArray* bswabe_pub_serialize(bswabe_pub_t* pub);
GByteArray* bswabe_cph_serialize(bswabe_cph_t* cph);

#if defined (__cplusplus)
} 
#endif

#endif // BSWABE_H
