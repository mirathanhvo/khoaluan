#include <stdlib.h>
#include <string.h>
#ifndef BSWABE_DEBUG
#define NDEBUG
#endif
#include <assert.h>
#include <openssl/sha.h>
#include <glib.h>
#include <relic.h>
#include <relic_conf.h>
#include <relic/relic.h>

#include "bswabe.h"
#include "private.h"
#include "common.h" 

/*
 * bswabe_setup:
 *   - Khởi tạo khóa công khai (pub) và master secret key (msk) sử dụng RELIC.
 */
void bswabe_setup(bswabe_pub_t** pub, bswabe_msk_t** msk, g1_t g, g2_t gp, bn_t alpha, bn_t beta, bn_t order) {
    // Allocate memory for public and master secret keys
    *pub = malloc(sizeof(bswabe_pub_t));
    *msk = malloc(sizeof(bswabe_msk_t));
    if (!*pub || !*msk) {
        raise_error("Memory allocation failed in bswabe_setup()");
    }

    // Copy beta to master secret key
    bn_null((*msk)->beta);
    bn_new((*msk)->beta);
    bn_copy((*msk)->beta, beta);

    // Compute g_alpha = gp^alpha
    g2_null((*msk)->g_alpha);
    g2_new((*msk)->g_alpha);
    g2_mul((*msk)->g_alpha, gp, alpha);

    // Compute h = g^beta
    g1_null((*pub)->h);
    g1_new((*pub)->h);
    g1_mul((*pub)->h, g, beta);

    // Compute e(g, g_alpha)
    gt_null((*pub)->g_hat_alpha);
    gt_new((*pub)->g_hat_alpha);
    pc_map((*pub)->g_hat_alpha, g, (*msk)->g_alpha);

    // Copy g, gp, and order to public key
    g1_null((*pub)->g);
    g1_new((*pub)->g);
    g1_copy((*pub)->g, g);

    g2_null((*pub)->gp);
    g2_new((*pub)->gp);
    g2_copy((*pub)->gp, gp);

    bn_null((*pub)->order);
    bn_new((*pub)->order);
    bn_copy((*pub)->order, order);

    // Debug output
    printf("Setup Phase:\n");
    printf("α: "); bn_print(alpha); printf("\n");
    printf("β: "); bn_print(beta); printf("\n");
    printf("g1: "); g1_print(g); printf("\n");
    printf("g2: "); g2_print(gp); printf("\n");
    printf("h = g1^β: "); g1_print((*pub)->h); printf("\n");
    printf("e(g1, g2)^α: ");
    int gt_size = gt_size_bin((*pub)->g_hat_alpha, 1);
    uint8_t* gt_buf = malloc(gt_size);
    if (!gt_buf) {
        raise_error("Memory allocation failed for gt_buf");
    }
    gt_write_bin(gt_buf, gt_size, (*pub)->g_hat_alpha, 1);
    for (int i = 0; i < gt_size; i++) {
        printf("%02x", gt_buf[i]);
    }
    printf("\n");
    free(gt_buf);
}

/*
 * bswabe_keygen: Sinh private key cho CP-ABE dựa trên khóa công khai (pub),
 * master secret key (msk) và danh sách các thuộc tính (attributes).
 */
bswabe_prv_t* bswabe_keygen(bswabe_pub_t* pub, bswabe_msk_t* msk, char** attributes) {
    bswabe_prv_t* prv;
    g2_t g_r, temp;
    bn_t r, beta_inv, order;

    // Allocate memory for the private key structure
    prv = malloc(sizeof(bswabe_prv_t));
    if (!prv) {
        raise_error("Memory allocation failed in bswabe_keygen()");
    }

    // Initialize group elements for the private key
    g2_null(prv->d); g2_new(prv->d);
    g2_null(g_r);    g2_new(g_r);
    g2_null(temp);   g2_new(temp);

    // Initialize big numbers
    bn_null(r);      bn_new(r);
    bn_null(beta_inv); bn_new(beta_inv);
    bn_null(order);  bn_new(order);

    // Get the group order
    g1_get_ord(order);

    // Generate a random value r and compute g_r = gp^r
    bn_rand_mod(r, order);
    g2_mul(g_r, pub->gp, r);

    // Compute the main private key component: d = (g_alpha * g_r)^(1/beta)
    g2_add(temp, msk->g_alpha, g_r);         // temp = g_alpha * g_r
    bn_mod_inv(beta_inv, msk->beta, order); // beta_inv = 1 / beta mod order
    g2_mul(prv->d, temp, beta_inv);         // d = temp^(1/beta)

    // Initialize the array to store attribute components
    prv->comps = g_array_new(FALSE, TRUE, sizeof(bswabe_prv_comp_t));
    if (!prv->comps) {
        raise_error("Memory allocation failed in g_array_new()");
    }

    // Process each attribute
    for (int i = 0; attributes[i]; i++) {
        bswabe_prv_comp_t c;

        // Copy the attribute name
        c.attr = strdup(attributes[i]);
        if (!c.attr) {
            raise_error("Memory allocation failed in strdup()");
        }

        // Generate a random value r_i for the attribute
        bn_t r;
        bn_null(r);
        bn_new(r);
        bn_rand_mod(r, order);

        g1_new(c.dp);
        g2_new(c.d);

        g1_t h_attr;
        g1_null(h_attr); g1_new(h_attr);

        // Map the attribute string to a group element in G1 using RELIC's ep_map
        ep_map(h_attr, (uint8_t*)attributes[i], strlen(attributes[i]));

        // Compute dp = H(attr)^(r_i)
        g1_mul(c.dp, h_attr, r);

        // Compute d = g^(r_i)
        g2_mul(c.d, pub->gp, r);

        // Normalize the components to ensure they are in canonical form
        g1_norm(c.dp, c.dp);
        g2_norm(c.d, c.d);

        // Debug: Print the attribute and its components
        printf("Keygen: Attribute: %s\n", c.attr);
        printf("  dp: "); g1_print(c.dp); printf("\n");
        printf("  d: "); g2_print(c.d); printf("\n");

        // Add the attribute component to the private key
        g_array_append_val(prv->comps, c);

        // Free temporary variables
        g1_free(h_attr);
        bn_free(r);
    }

    // Update the number of attribute components
    prv->comps_len = prv->comps->len;

    // Debug: Print the total number of attributes added
    printf("Debug: Number of attributes added = %d\n", (int)prv->comps->len);

    // Free temporary variables
    bn_free(order);
    bn_free(beta_inv);
    g2_free(g_r);
    g2_free(temp);

    return prv;
}
