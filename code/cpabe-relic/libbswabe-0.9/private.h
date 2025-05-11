#ifndef PRIVATE_H
#define PRIVATE_H

#ifdef __cplusplus
extern "C" {
#endif



/* PUBLIC KEY */
struct bswabe_pub_s {
    g1_t g;             // generator in G1
    g2_t gp;            // generator in G2
    gt_t g_hat_alpha;   // e(g, g)^α in GT
    g1_t h;             // h = g^β
    bn_t order;         // group order
};

/* MASTER SECRET KEY */
struct bswabe_msk_s {
    g2_t g_alpha;       // g^α in G2
    bn_t beta;          // β in Z_r
};

/* PRIVATE KEY COMPONENT */
typedef struct {
    char* attr;         // attribute name
    g2_t d;             // component in G2
    g1_t dp;            // component in G1
    int used;           // used during decryption
} bswabe_prv_comp_t;

/* USER PRIVATE KEY */
struct bswabe_prv_s {
    g2_t d;             // main component in G2
    GArray* comps;      // array of components (changed to GArray)
    int comps_len;      // number of components
};

/* POLYNOMIAL STRUCTURE */
typedef struct {
    int deg;
    bn_t* coef;         // coefficient array of size deg + 1
} bswabe_polynomial_t;

/* ACCESS POLICY NODE */
typedef struct bswabe_policy_s {
    int k;                         // threshold k-out-of-n
    char* attr;                    // attribute name if leaf; NULL otherwise

    GPtrArray* children;
    int children_len;                   // number of children

    bswabe_polynomial_t* q;       // polynomial q(x) used in encryption

    int satisfiable;
    int min_leaves;
    int attri;
    GArray* satl;
    int satl_len;

    g1_t c;  // component in G1 (encryption)
    g2_t cp; // component in G2 (encryption)
} bswabe_policy_t;

/* CIPHERTEXT STRUCTURE */
struct bswabe_cph_s {
    gt_t cs;                      // masked message in GT
    g1_t c;                       // additional component in G1
    bswabe_policy_t* p;          // root of access policy tree
};

#ifdef __cplusplus
}
#endif

#endif // PRIVATE_H
