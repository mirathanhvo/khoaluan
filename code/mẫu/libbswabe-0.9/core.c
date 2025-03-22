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

// nếu chưa có, thêm prototype
void hash_attr(g1_t h, char* attr);
void hash_attr2(g1_t h, char* attr);
void print_bn(bn_t n);
void print_g1(const char *label, g1_t a);
void print_g2(const char *label, g2_t a);

// định nghĩa hàm nếu chưa có
void hash_attr(g1_t h, char* attr) {
    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256((uint8_t*)attr, strlen(attr), digest);
    g1_map(h, digest, SHA256_DIGEST_LENGTH);
}

void hash_attr2(g1_t h, char* attr) {
    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256((uint8_t*)attr, strlen(attr), digest);
    g1_map(h, digest, SHA256_DIGEST_LENGTH);
}

/*
 * bswabe_setup:
 *   - Khởi tạo khóa công khai (pub) và master secret key (msk) sử dụng RELIC.
 */
void bswabe_setup(bswabe_pub_t** pub, bswabe_msk_t** msk) {
    bn_t alpha, order;
    g1_t g;
    g2_t gp;

    *pub = malloc(sizeof(bswabe_pub_t));
    *msk = malloc(sizeof(bswabe_msk_t));
    if (!*pub || !*msk) {
        raise_error("Memory allocation failed in bswabe_setup()");
    }

    bn_null(alpha); bn_new(alpha);
    bn_null(order); bn_new(order);

    g1_null(g); g1_new(g);
    g2_null(gp); g2_new(gp);

    g1_get_ord(order);
    g1_rand(g);
    g2_rand(gp);
    bn_rand_mod(alpha, order);

    bn_null((*msk)->beta); 
    bn_new((*msk)->beta);
    bn_rand_mod((*msk)->beta, order);

    g2_null((*msk)->g_alpha);
    g2_new((*msk)->g_alpha);
    g2_mul((*msk)->g_alpha, gp, alpha);

    g1_null((*pub)->h);
    g1_new((*pub)->h);
    g1_mul((*pub)->h, g, (*msk)->beta);

    gt_null((*pub)->g_hat_alpha);
    gt_new((*pub)->g_hat_alpha);
    pc_map((*pub)->g_hat_alpha, g, (*msk)->g_alpha);

    g1_null((*pub)->g);
    g1_new((*pub)->g);
    g2_null((*pub)->gp);
    g2_new((*pub)->gp);
    g1_copy((*pub)->g, g);
    g2_copy((*pub)->gp, gp);

    bn_null((*pub)->order);
    bn_new((*pub)->order);
    bn_copy((*pub)->order, order);

    // Debug prints
    printf("Setup Phase:\n");
    printf("α: ");
    print_bn(alpha);  // Hàm print_bn in bn_t dưới dạng hex
    printf("β: ");
    print_bn((*msk)->beta);
    print_g1("g1", g);
    print_g2("g2", gp);
    print_g1("h = g1^β", (*pub)->h);
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

    bn_free(alpha);
    bn_free(order);
    g1_free(g);
    g2_free(gp);
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
        hash_attr(h_attr, attributes[i]);
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
        hash_attr2(h_attr2, attributes[i]);
        g1_mul(c.zp, h_attr2, r);

        g1_norm(c.zp, c.zp);
        g2_norm(c.z, c.z);

        // --- Bổ sung in ra thông tin cho mỗi thành phần thuộc tính ---
        printf("Keygen: Attribute: %s\n", c.attr);
        print_g1("  dp", c.dp);
        print_g2("  d", c.d);
        print_g1("  zp", c.zp);
        print_g2("  z", c.z);
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
