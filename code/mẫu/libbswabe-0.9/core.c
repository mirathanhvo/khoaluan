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

    prv = malloc(sizeof(bswabe_prv_t));
    if (!prv) {
        raise_error("Memory allocation failed in bswabe_keygen()");
    }

    g2_null(prv->d); g2_new(prv->d);
    g2_null(g_r);    g2_new(g_r);
    g2_null(temp);   g2_new(temp);

    bn_null(r);      bn_new(r);
    bn_null(beta_inv); bn_new(beta_inv);
    bn_null(order);  bn_new(order);

    g1_get_ord(order);
    bn_rand_mod(r, order);
    g2_mul(g_r, pub->gp, r);

    g2_add(temp, msk->g_alpha, g_r);
    bn_mod_inv(beta_inv, msk->beta, order);
    g2_mul(prv->d, temp, beta_inv);

    prv->comps = g_array_new(FALSE, TRUE, sizeof(bswabe_prv_comp_t));
    if (!prv->comps) {
        raise_error("Memory allocation failed in g_array_new()");
    }

    for (int i = 0; attributes[i]; i++) {
        bswabe_prv_comp_t c;

        // Copy tên thuộc tính
        c.attr = strdup(attributes[i]);
        if (!c.attr) {
            raise_error("Memory allocation failed in strdup()");
        }

        // Sinh số ngẫu nhiên r_i
        bn_t r;
        bn_null(r);
        bn_new(r);
        bn_rand_mod(r, order);

        // Tính toán các thành phần của thành phần thuộc tính:
        // d = g^{r_i} (G2), dp = H(attr)^{r_i} (G1)
        // Và các thành phần mở rộng nếu có: z = gp^{r_i} (G2), zp = H'(attr)^{r_i} (G1)
        g1_new(c.dp); g1_new(c.zp);
        g2_new(c.d); g2_new(c.z);

        // dp = H(attr)^{r_i}
        g1_t h_attr;
        g1_null(h_attr); g1_new(h_attr);
        element_from_string(h_attr, attributes[i]); // Use element_from_string instead of hash_attr

        // Debug: In ra giá trị ánh xạ của thuộc tính ở keygen
        int size = g1_size_bin(h_attr, 1);
        uint8_t* buf = malloc(size);
        g1_write_bin(buf, size, h_attr, 1);
        printf("DEBUG keygen: Mapped attribute '%s' in G1: ", attributes[i]);
        for (int j = 0; j < size; j++) {
            printf("%02x", buf[j]);
        }
        printf("\n");
        free(buf);

        g1_mul(c.dp, h_attr, r);

        // d = g^{r_i}
        g2_mul_gen(c.d, r);

        // Chuẩn hóa các thành phần
        g1_norm(c.dp, c.dp);
        g2_norm(c.d, c.d);

        // Nếu hệ thống bạn sử dụng các thành phần mở rộng:
        g2_mul(c.z, pub->gp, r);
        g1_t h_attr2;
        g1_null(h_attr2); g1_new(h_attr2);
        element_from_string(h_attr2, attributes[i]); // Use element_from_string instead of hash_attr2
        g1_mul(c.zp, h_attr2, r);

        g1_norm(c.zp, c.zp);
        g2_norm(c.z, c.z);

        // --- Bổ sung in ra thông tin cho mỗi thành phần thuộc tính ---
        printf("Keygen: Attribute: %s\n", c.attr);
        printf("  dp: "); g1_print(c.dp); printf("\n");
        printf("  d: "); g2_print(c.d); printf("\n");
        printf("  zp: "); g1_print(c.zp); printf("\n");
        printf("  z: "); g2_print(c.z); printf("\n");
        // -------------------------------------------------------

        g_array_append_val(prv->comps, c);

        bn_free(r);
    }

    // Cập nhật comps_len sau khi thêm tất cả các attribute components
    prv->comps_len = prv->comps->len;

    // Debug: In ra số lượng thuộc tính được thêm
    printf("Debug: Number of attributes added = %d\n", (int)prv->comps->len);

    bn_free(order);
    bn_free(r);
    bn_free(beta_inv);
    g2_free(g_r);
    g2_free(temp);

    return prv;
}