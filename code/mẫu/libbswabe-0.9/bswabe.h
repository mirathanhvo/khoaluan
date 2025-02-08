#ifndef BSWABE_H
#define BSWABE_H

#include <relic/relic.h>

#if defined (__cplusplus)
extern "C" {
#endif

typedef struct bswabe_pub_s bswabe_pub_t;
typedef struct bswabe_msk_s bswabe_msk_t;
typedef struct bswabe_prv_s bswabe_prv_t;
typedef struct bswabe_cph_s bswabe_cph_t;

void bswabe_setup( bswabe_pub_t** pub, bswabe_msk_t** msk );
bswabe_prv_t* bswabe_keygen( bswabe_pub_t* pub, bswabe_msk_t* msk, char** attributes );

bswabe_cph_t* bswabe_enc( bswabe_pub_t* pub, gt_t m, char* policy );
int bswabe_dec( bswabe_pub_t* pub, bswabe_prv_t* prv, bswabe_cph_t* cph, gt_t m );

void bswabe_pub_free( bswabe_pub_t* pub );
void bswabe_msk_free( bswabe_msk_t* msk );
void bswabe_prv_free( bswabe_prv_t* prv );
void bswabe_cph_free( bswabe_cph_t* cph );

char* bswabe_error();

#if defined (__cplusplus)
} // extern "C"
#endif

#endif
