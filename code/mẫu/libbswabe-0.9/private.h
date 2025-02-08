/*
    No need to include glib.h, only RELIC is required
*/

#ifndef PRIVATE_H
#define PRIVATE_H

#include <relic.h>

struct bswabe_pub_s {
    char* pairing_desc;
    g1_t g;           /* G_1 */
    g1_t h;           /* G_1 */
    g2_t gp;          /* G_2 */
    gt_t g_hat_alpha; /* G_T */
};

struct bswabe_msk_s {
    bn_t beta;    /* Z_r */
    g2_t g_alpha; /* G_2 */
};

typedef struct {
    char* attr;
    g2_t d;  /* G_2 */
    g2_t dp; /* G_2 */
    int used;
    g1_t z;  /* G_1 */
    g1_t zp; /* G_1 */
} bswabe_prv_comp_t;

struct bswabe_prv_s {
    g2_t d;   /* G_2 */
    bswabe_prv_comp_t* comps; /* Dynamic array replacing GArray */
    int comps_len;  /* Number of elements in comps */
};

typedef struct {
    int deg;
    gt_t* coef; /* G_T (of length deg + 1) */
} bswabe_polynomial_t;

typedef struct bswabe_policy_s {
    int k;
    char* attr;
    g1_t c;
    g1_t cp;
    struct bswabe_policy_s** children; /* Pointer array replacing GPtrArray */
    int children_len;
    bswabe_polynomial_t* q;
    int satisfiable;
    int min_leaves;
    int attri;
    int* satl; /* Dynamic array replacing GArray */
    int satl_len;
} bswabe_policy_t;

struct bswabe_cph_s {
    gt_t cs; /* G_T */
    g1_t c;  /* G_1 */
    bswabe_policy_t* p;
};

#endif // PRIVATE_H
