#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef BSWABE_DEBUG
#define NDEBUG
#endif
#include <assert.h>
#include <openssl/sha.h>
#include <glib.h>
#include <relic/relic.h>
#include <relic_conf.h>
#include <relic/relic.h>
#include "bswabe.h"
#include "private.h"

void die(const char* fmt, ...);

/*
 * bswabe_setup:
 *   - Khởi tạo khóa công khai (pub) và master secret key (msk) sử dụng RELIC.
 */
void bswabe_setup(bswabe_pub_t** pub, bswabe_msk_t** msk) {
    bn_t alpha, beta, order;
    g1_t g;
    g2_t gp;

    bn_null(alpha); bn_new(alpha);
    bn_null(beta);  bn_new(beta);
    bn_null(order); bn_new(order);
    g1_null(g);     g1_new(g);
    g2_null(gp);    g2_new(gp);

    g1_get_ord(order);
    bn_rand_mod(alpha, order);
    bn_rand_mod(beta, order);
    g1_get_gen(g);
    g2_get_gen(gp);

    *pub = malloc(sizeof(bswabe_pub_t));
    *msk = malloc(sizeof(bswabe_msk_t));

    bn_null((*msk)->beta); bn_new((*msk)->beta); bn_copy((*msk)->beta, beta);
    g2_null((*msk)->g_alpha); g2_new((*msk)->g_alpha);
    g2_mul((*msk)->g_alpha, gp, alpha);

    g1_null((*pub)->g); g1_new((*pub)->g); g1_copy((*pub)->g, g);
    g2_null((*pub)->gp); g2_new((*pub)->gp); g2_copy((*pub)->gp, gp);
    g1_null((*pub)->h); g1_new((*pub)->h); g1_mul((*pub)->h, g, beta);
    gt_null((*pub)->g_hat_alpha); gt_new((*pub)->g_hat_alpha);
    pc_map((*pub)->g_hat_alpha, g, (*msk)->g_alpha);
    bn_null((*pub)->order); bn_new((*pub)->order); bn_copy((*pub)->order, order);

    bn_free(alpha); bn_free(beta); bn_free(order);
    g1_free(g); g2_free(gp);
}

/*
 * bswabe_keygen: Sinh private key cho CP-ABE dựa trên khóa công khai (pub),
 * master secret key (msk) và danh sách các thuộc tính (attributes).
 */
bswabe_prv_t* bswabe_keygen(bswabe_pub_t* pub, bswabe_msk_t* msk, char** attributes) {
    printf("[DEBUG] Attributes passed into bswabe_keygen:\n");
    for (int i = 0; attributes[i]; i++) {
        printf(" - %s\n", attributes[i]);
    }

    bswabe_prv_t* prv = malloc(sizeof(bswabe_prv_t));
    if (!prv)
        die("Memory allocation failed in bswabe_keygen()");

    bn_t r, beta_inv, order;
    g2_t g_r2, temp;

    bn_null(r);        bn_new(r);
    bn_null(beta_inv); bn_new(beta_inv);
    bn_null(order);    bn_new(order);
    g2_null(g_r2);     g2_new(g_r2);
    g2_null(temp);     g2_new(temp);
    g2_null(prv->d);   g2_new(prv->d);

    g1_get_ord(order);
    bn_rand_mod(r, order);

    // G2: g^r
    g2_mul(g_r2, pub->gp, r);    // pub->gp ∈ G2

    // Tính D = (g_alpha * g^r)^1/β ∈ G2
    g2_mul(temp, msk->g_alpha, r);         // g_alpha^r
    bn_mod_inv(beta_inv, msk->beta, order);
    g2_mul(prv->d, temp, beta_inv);        // D = g_alpha^r / β

    // Tạo danh sách thành phần khóa
    prv->comps = g_array_new(FALSE, TRUE, sizeof(bswabe_prv_comp_t));

    for (int i = 0; attributes[i]; i++) {
        bswabe_prv_comp_t c;
        bn_t ri;

        char norm_attr[256];
        normalize_attr(norm_attr, attributes[i]);
        c.attr = strdup(norm_attr);

        bn_null(ri); bn_new(ri);
        bn_rand_mod(ri, order);

        // G2: D_j = g^r * g^ri ∈ G2
        g2_t g_ri2;
        g2_null(g_ri2); g2_new(g_ri2);
        g2_mul(g_ri2, pub->gp, ri);     // g^ri in G2
        g2_null(c.d); g2_new(c.d);
        g2_add(c.d, g_r2, g_ri2);       // D_j = g^r * g^ri in G2
        g2_norm(c.d, c.d);
        g2_free(g_ri2);

        // G1: dp = H(attr)^ri ∈ G1
        g1_t h_attr;
        g1_null(h_attr); g1_new(h_attr);
        ep_map(h_attr, (uint8_t*)norm_attr, strlen(norm_attr));  // map H(attr) ∈ G1
        g1_norm(h_attr, h_attr);

        g1_null(c.dp); g1_new(c.dp);
        g1_mul(c.dp, h_attr, ri);
        g1_norm(c.dp, c.dp);
        g1_free(h_attr);

        g_array_append_val(prv->comps, c);

        bn_free(ri);
    }

    prv->comps_len = prv->comps->len;

    bn_free(r); bn_free(beta_inv); bn_free(order);
    g2_free(g_r2); g2_free(temp);


    printf("========= PRIVATE KEY ATTRIBUTES =========\n");
    for (int i = 0; i < prv->comps->len; i++) {
        bswabe_prv_comp_t* c = &g_array_index(prv->comps, bswabe_prv_comp_t, i);
        printf("Attribute [%d]: %s\n", i, c->attr);
    
        // In d ∈ G2
        int size = g2_size_bin(c->d, 1);
        uint8_t* buf = malloc(size);
        g2_write_bin(buf, size, c->d, 1);
        printf("  d  ∈ G2 = ");
        for (int j = 0; j < size; j++) printf("%02x", buf[j]);
        printf("\n");
        free(buf);
    
        // In dp ∈ G1
        size = g1_size_bin(c->dp, 1);
        buf = malloc(size);
        g1_write_bin(buf, size, c->dp, 1);
        printf("  dp ∈ G1 = ");
        for (int j = 0; j < size; j++) printf("%02x", buf[j]);
        printf("\n");
        free(buf);
    }
    return prv;
}

/* ======= Hàm khởi tạo nút policy ======= */
bswabe_policy_t* base_node(int k, char* s) {
    bswabe_policy_t* p = malloc(sizeof(bswabe_policy_t));
    if (!p) {
        fprintf(stderr, "Memory allocation failed in base_node()\n");
        exit(1);
    }

    p->k = k;
    p->attr = s ? strdup(s) : NULL;
    p->children = g_ptr_array_new();
    p->q = NULL;
    p->satisfiable = 0;
    p->min_leaves = 0;
    p->attri = -1;
    p->satl = NULL;
    g1_null(p->c);
    g2_null(p->cp);

    return p;
}

/* ======= parse_policy_postfix: chuyển chuỗi postfix -> cây policy ======= */
bswabe_policy_t* parse_policy_postfix(char* s) {
    char** toks = g_strsplit(s, " ", 0);
    char** cur_toks = toks;
    GPtrArray* stack = g_ptr_array_new();
    bswabe_policy_t* root = NULL;

    while (*cur_toks) {
        char* tok = *(cur_toks++);
        if(!tok || !*tok) continue;
        
        // In debug token
        printf("Processing token: %s\n", tok);
        
        int k, n;
        if (sscanf(tok, "%dof%d", &k, &n) != 2) {
            // Nút lá
            g_ptr_array_add(stack, base_node(1, tok));
        } else {
            if(k < 1 || k > n || n == 1 || (int)stack->len < n) {
                fprintf(stderr, "error parsing policy string\n");
                g_ptr_array_free(stack, TRUE);
                g_strfreev(toks);
                return NULL;
            }
            bswabe_policy_t* node = base_node(k, NULL);
            g_ptr_array_set_size(node->children, n);
            for(int i = n - 1; i >= 0; i--) {
                node->children->pdata[i] = g_ptr_array_remove_index(stack, stack->len - 1);
            }
            g_ptr_array_add(stack, node);
        }
    }
    if (stack->len != 1) {
        fprintf(stderr, "error parsing policy string (extra tokens)\n");
        // Debug print: print the remaining tokens on the stack
        for (int i = 0; i < stack->len; i++) {
            bswabe_policy_t* node = g_ptr_array_index(stack, i);
            printf("Remaining token on stack: %s\n", node->attr ? node->attr : "non-leaf node");
        }
        g_ptr_array_free(stack, TRUE);
        g_strfreev(toks);
        return NULL;
    }
    root = g_ptr_array_index(stack, 0);
    g_ptr_array_free(stack, TRUE);
    g_strfreev(toks);
    return root;
}

/* ======= rand_poly: sinh đa thức bậc deg trong Zr, q(0)=zero_val ======= */
bswabe_polynomial_t* rand_poly(int deg, bn_t zero_val, bn_t order) {
    bswabe_polynomial_t* q = malloc(sizeof(bswabe_polynomial_t));
    if(!q) {
        fprintf(stderr, "Memory allocation failed in rand_poly()\n");
        exit(1);
    }
    q->deg = deg;
    q->coef = malloc(sizeof(bn_t) * (deg + 1));
    if(!q->coef) {
        free(q);
        fprintf(stderr, "Memory allocation failed in rand_poly()\n");
        exit(1);
    }
    for(int i = 0; i <= deg; i++) {
        bn_null(q->coef[i]);
        bn_new(q->coef[i]);
    }
    bn_copy(q->coef[0], zero_val);

    // In giá trị của q->coef[0] ngay sau khi gọi bn_copy
    int coef_size = bn_size_bin(q->coef[0]);
    uint8_t* coef_buf = malloc(coef_size);
    bn_write_bin(coef_buf, coef_size, q->coef[0]);
    printf("Value of q->coef[0]: ");
    for (int i = 0; i < coef_size; i++) {
        printf("%02x", coef_buf[i]);
    }
    printf("\n");
    free(coef_buf);

    for(int i = 1; i <= deg; i++) {
        bn_rand_mod(q->coef[i], order);
    }
    return q;
}

/* ======= eval_poly: tính q(x) trong Zr ======= */
void eval_poly(bn_t r, bswabe_polynomial_t* q, bn_t x, bn_t order) {
    bn_t s, t;
    bn_null(s); bn_new(s);
    bn_null(t); bn_new(t);

    bn_zero(r);
    bn_set_dig(t, 1);

    for(int i = 0; i <= q->deg; i++) {
        bn_mul(s, q->coef[i], t);
        bn_mod(s, s, order);
        bn_add(r, r, s);
        bn_mod(r, r, order);

        bn_mul(t, t, x);
        bn_mod(t, t, order);
    }
    bn_free(s);
    bn_free(t);
}

/* ======= fill_policy: chia sẻ bí mật s (bn_t) cho cây policy ======= */
void fill_policy(bswabe_policy_t* p, bswabe_pub_t* pub, bn_t s) {
    p->q = rand_poly(p->k - 1, s, pub->order);
    if (p->children->len == 0) {
        g1_new(p->c);
        g2_new(p->cp);

        // Chuẩn hóa thuộc tính
        char norm_attr[256];
        normalize_attr(norm_attr, p->attr);

        uint8_t* attr_bytes = (uint8_t*)norm_attr;
        size_t attr_len = strlen(norm_attr);

        // Map attribute to G1 using RELIC's ep_map
        g1_t h_attr;
        g1_null(h_attr); g1_new(h_attr);
        ep_map(h_attr, attr_bytes, attr_len);

        // Debug: Print the mapped attribute in G1
        int size = g1_size_bin(h_attr, 1);
        uint8_t* buf = malloc(size);
        g1_write_bin(buf, size, h_attr, 1);
        printf("DEBUG fill_policy: Mapped attribute '%s' in G1: ", norm_attr);
        for (int j = 0; j < size; j++) {
            printf("%02x", buf[j]);
        }
        printf("\n");
        free(buf);

        // Compute p->c = H(attr)^q(0)
        g1_mul(p->c, h_attr, p->q->coef[0]);

        // Map attribute to G2 using RELIC's ep2_map
        g2_t h2_attr;
        g2_null(h2_attr); g2_new(h2_attr);
        ep2_map(h2_attr, attr_bytes, attr_len);

        // Compute p->cp = H2(attr)^q(0)
        g2_mul(p->cp, h2_attr, p->q->coef[0]);

        // Debug: Print the mapped attribute in G2
        size = g2_size_bin(h2_attr, 1);
        buf = malloc(size);
        g2_write_bin(buf, size, h2_attr, 1);
        printf("DEBUG fill_policy: Mapped attribute '%s' in G2: ", norm_attr);
        for (int j = 0; j < size; j++) {
            printf("%02x", buf[j]);
        }
        printf("\n");
        free(buf);

        // Debug: Print p->c and p->cp
        size = g1_size_bin(p->c, 1);
        buf = malloc(size);
        g1_write_bin(buf, size, p->c, 1);
        printf("DEBUG fill_policy: p->c for '%s': ", norm_attr);
        for (int j = 0; j < size; j++) {
            printf("%02x", buf[j]);
        }
        printf("\n");
        free(buf);

        size = g2_size_bin(p->cp, 1);
        buf = malloc(size);
        g2_write_bin(buf, size, p->cp, 1);
        printf("DEBUG fill_policy: p->cp for '%s': ", norm_attr);
        for (int j = 0; j < size; j++) {
            printf("%02x", buf[j]);
        }
        printf("\n");
        free(buf);

        // Normalize elements
        g1_norm(p->c, p->c);
        g2_norm(p->cp, p->cp);

        // Free temporary variables
        g1_free(h_attr);
        g2_free(h2_attr);
    } else {
        bn_t r, t;
        bn_null(r); bn_new(r);
        bn_null(t); bn_new(t);

        for (int i = 0; i < (int)p->children->len; i++) {
            bn_set_dig(r, i + 1);
            eval_poly(t, p->q, r, pub->order);
            fill_policy(g_ptr_array_index(p->children, i), pub, t);
        }

        bn_free(r);
        bn_free(t);
    }
}

/* ======= bswabe_enc: mã hóa ======= */
bswabe_cph_t* bswabe_enc(bswabe_pub_t* pub, gt_t m, char* policy) {
   // Allocate memory for the ciphertext structure
   bswabe_cph_t* cph = malloc(sizeof(bswabe_cph_t));
   if (!cph) {
       fprintf(stderr, "ERROR: Memory allocation failed for bswabe_cph_t.\n");
       return NULL;
   }

   // Generate a random GT element for m
   gt_new(m);
   gt_rand(m);
   gt_norm(m);


   {
       int size = gt_size_bin(m, 1);
       uint8_t* buf = malloc(size);
       if (!buf) {
           fprintf(stderr, "Memory allocation failed in bswabe_enc() debug print\n");
           exit(1);
       }
       gt_write_bin(buf, size, m, 1);
       printf("[core][enc] m = ");
       for (int i = 0; i < size; i++) {
           printf("%02x", buf[i]);
       }
       printf("\n");
       free(buf);
   }

   // Generate a random secret s in Zr
   bn_t s;
   bn_null(s);
   bn_new(s);
   bn_rand_mod(s, pub->order);

   // Compute cs = m * e(pub->g_hat_alpha, s)
   gt_new(cph->cs);
   gt_t tmp;
   gt_new(tmp);
   gt_exp(tmp, pub->g_hat_alpha, s); // tmp = e(g_hat_alpha, s)
   gt_mul(cph->cs, m, tmp);          // cph->cs = m * tmp
   gt_norm(cph->cs);
   gt_free(tmp);

   printf("[enc] cs = m * e(g_hat_alpha, s):\n");
   {
       int size = gt_size_bin(cph->cs, 1);
       uint8_t* buf = malloc(size);
       if (!buf) {
           fprintf(stderr, "Memory allocation failed while printing cph->cs\n");
           exit(1);
       }
       gt_write_bin(buf, size, cph->cs, 1);
       for (int i = 0; i < size; i++) {
           printf("%02x", buf[i]);
       }
       printf("\n");
       free(buf);
   }

   // Compute c = h^s
   g1_new(cph->c);
   g1_mul(cph->c, pub->h, s);        // cph->c = h^s

   // Parse the policy string into a policy tree
   cph->p = parse_policy_postfix(policy);
   if (!cph->p) {
       fprintf(stderr, "ERROR: Failed to parse policy string.\n");
       g1_free(cph->c);
       gt_free(cph->cs);
       free(cph);
       return NULL;
   }

   // Share the secret s according to the policy tree
   fill_policy(cph->p, pub, s);

   // Free the secret s as it is no longer needed
   bn_free(s);

   return cph;
}

/* ======= check_sat: duyệt cây policy để đánh dấu các nút thỏa mãn ======= */
void check_sat(bswabe_policy_t* p, bswabe_prv_t* prv) {
    if (p->children->len == 0) {
        // Nút lá
        p->satisfiable = 0;

        // Chuẩn hóa thuộc tính của policy
        char norm_policy_attr[256];
        normalize_attr(norm_policy_attr, p->attr);

        for (int i = 0; i < prv->comps->len; i++) {
            bswabe_prv_comp_t* comp = &g_array_index(prv->comps, bswabe_prv_comp_t, i);

            // Chuẩn hóa thuộc tính của private key
            char norm_key_attr[256];
            normalize_attr(norm_key_attr, comp->attr);

            // Debug: In ra giá trị so sánh thuộc tính
            printf("[check_sat] leaf: policy_attr='%s', key_attr='%s'\n", norm_policy_attr, norm_key_attr);

            if (strcmp(norm_policy_attr, norm_key_attr) == 0) {
                p->satisfiable = 1;
                p->attri = i;
                printf("[check_sat] match => satisfiable=1, attri=%d\n", i);
                break;
            }
        }
    } else {
        // Nút nội
        p->satl = g_array_new(FALSE, TRUE, sizeof(int));
        int sat_count = 0;
        for (int i = 0; i < p->children->len; i++) {
            bswabe_policy_t* child = g_ptr_array_index(p->children, i);
            check_sat(child, prv);
            if (child->satisfiable) {
                int idx = i + 1;
                g_array_append_val(p->satl, idx);
                sat_count++;
            }
        }
        // Debug: In toàn bộ mảng p->satl và số lượng
        printf("[check_sat] node(k=%d): sat_count=%d, needed=%d\n", p->k, sat_count, p->k);
        printf("[check_sat] p->satl contents: ");
        for (int i = 0; i < p->satl->len; i++) {
            printf("%d ", g_array_index(p->satl, int, i));
        }
        printf("\n");
        p->satisfiable = (sat_count >= p->k) ? 1 : 0;
        printf("[check_sat] => satisfiable=%d\n", p->satisfiable);
    }
}

bswabe_policy_t* cur_comp_pol;

/* ======= cmp_int: hàm so sánh cho qsort ======= */
int cmp_int(const void* a, const void* b) {
    int idx_a = *(const int*)a;
    int idx_b = *(const int*)b;

    int min_a = ((bswabe_policy_t*) g_ptr_array_index(cur_comp_pol->children, idx_a))->min_leaves;
    int min_b = ((bswabe_policy_t*) g_ptr_array_index(cur_comp_pol->children, idx_b))->min_leaves;

    if (min_a < min_b) return -1;
    if (min_a > min_b) return 1;
    return 0;
}

/* ======= pick_sat_min_leaves: tính số nút lá tối thiểu cần thiết ======= */
void pick_sat_min_leaves(bswabe_policy_t* p, bswabe_prv_t* prv) {
    if (p->children->len == 0) {
        p->min_leaves = p->satisfiable ? 1 : 1000000;
        printf("[pick_sat_min_leaves] leaf '%s' => satisfiable=%d => min_leaves=%d\n",
               p->attr, p->satisfiable, p->min_leaves);
    } else {
        for (int i = 0; i < p->children->len; i++) {
            bswabe_policy_t* child = g_ptr_array_index(p->children, i);
            if (child->satisfiable)
                pick_sat_min_leaves(child, prv);
        }

        int n = p->children->len;
        int* c = malloc(sizeof(int) * n);
        for (int i = 0; i < n; i++)
            c[i] = i;

        cur_comp_pol = p;
        qsort(c, n, sizeof(int), cmp_int);

        p->satl = g_array_new(FALSE, TRUE, sizeof(int));
        p->min_leaves = 0;
        int l = 0;

        for (int i = 0; i < n && l < p->k; i++) {
            bswabe_policy_t* child = g_ptr_array_index(p->children, c[i]);
            if (child->satisfiable) {
                l++;
                p->min_leaves += child->min_leaves;
                int idx = c[i] + 1;  // +1 vì satl dùng chỉ số bắt đầu từ 1
                g_array_append_val(p->satl, idx);
            }
        }

        free(c);
        assert(l == p->k);  // Đảm bảo đủ k con thỏa mãn
        printf("[pick_sat_min_leaves] => p->min_leaves=%d\n", p->min_leaves);
    }
}

/* ======= lagrange_coef (trong Zr) ======= */
void lagrange_coef(bn_t r, GArray* s, int i, bn_t order) {
    bn_t t;
    bn_null(t); 
    bn_new(t);
    bn_set_dig(r, 1); // Initialize r to 1

    for (int idx = 0; idx < (int)s->len; idx++) {
        int j = g_array_index(s, int, idx);
        if (j == i) 
            continue;

        // Calculate (-j)
        bn_set_dig(t, j);
        bn_neg(t, t);
        bn_mod(t, t, order);
        bn_mul(r, r, t);
        bn_mod(r, r, order);

        // Calculate (i - j)
        bn_set_dig(t, i - j);
        bn_mod(t, t, order);
        bn_mod_inv(t, t, order); // Modular inverse of (i - j)
        bn_mul(r, r, t);
        bn_mod(r, r, order);
    }
    bn_free(t);
}

/* ======= dec_leaf_naive: giải mã nút lá ======= */
void dec_leaf_naive(gt_t r, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub) {
    bswabe_prv_comp_t* c = &(g_array_index(prv->comps, bswabe_prv_comp_t, p->attri));
    gt_t A, B;
    gt_new(A); gt_new(B);

    // Chuẩn hóa các phần tử trước khi gọi pc_map
    g1_norm(p->c, p->c);
    g2_norm(c->d, c->d);
    g1_norm(c->dp, c->dp);
    g2_norm(p->cp, p->cp);

    // In giá trị của các phần tử trước khi gọi pc_map
    int size;
    uint8_t* buf;

    size = g1_size_bin(p->c, 1);
    buf = malloc(size);
    if (!buf) {
        die("Memory allocation failed for debug buffer.\n");
    }
    g1_write_bin(buf, size, p->c, 1);
    printf("p->c: ");
    for (int i = 0; i < size; i++) printf("%02x", buf[i]);
    printf("\n");
    free(buf);

    size = g2_size_bin(c->d, 1);
    buf = malloc(size);
    if (!buf) {
        die("Memory allocation failed for debug buffer.\n");
    }
    g2_write_bin(buf, size, c->d, 1);
    printf("c->d: ");
    for (int i = 0; i < size; i++) printf("%02x", buf[i]);
    printf("\n");
    free(buf);

    size = g1_size_bin(c->dp, 1);
    buf = malloc(size);
    if (!buf) {
        die("Memory allocation failed for debug buffer.\n");
    }
    g1_write_bin(buf, size, c->dp, 1);
    printf("c->dp: ");
    for (int i = 0; i < size; i++) printf("%02x", buf[i]);
    printf("\n");
    free(buf);

    size = g2_size_bin(p->cp, 1);
    buf = malloc(size);
    if (!buf) {
        die("Memory allocation failed for debug buffer.\n");
    }
    g2_write_bin(buf, size, p->cp, 1);
    printf("p->cp: ");
    for (int i = 0; i < size; i++) printf("%02x", buf[i]);
    printf("\n");
    free(buf);

    pc_map(A, p->c, c->d);
    pc_map(B, c->dp, p->cp);
    gt_inv(B, B);
    gt_mul(r, A, B);
    
    gt_free(A); gt_free(B);
}

void dec_node_naive(gt_t r, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub);

/* dec_internal_naive: giải mã nút nội */
void dec_internal_naive(gt_t r, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub) {
    gt_t temp;
    bn_t coef;

    gt_new(temp);
    bn_new(coef);
    gt_set_unity(r);

    printf("[dec_internal_naive] p->satl contents: ");
    for (int idx = 0; idx < p->satl->len; idx++) {
        printf("%d ", g_array_index(p->satl, int, idx));
    }
    printf("\n");

    for (int i = 0; i < p->satl->len; i++) {
        int idx = g_array_index(p->satl, int, i) - 1;
        dec_node_naive(temp, g_ptr_array_index(p->children, idx), prv, pub);
        lagrange_coef(coef, p->satl, g_array_index(p->satl, int, i), pub->order);

        gt_exp(temp, temp, coef);

        int size = gt_size_bin(temp, 1);
        uint8_t* buf = malloc(size);
        gt_write_bin(buf, size, temp, 1);
        printf("[dec_internal_naive] temp after exp: ");
        for (int j = 0; j < size; j++) {
            printf("%02x", buf[j]);
        }
        printf("\n");
        free(buf);

        gt_mul(r, r, temp);
        gt_norm(r); // Ensure canonical representation
    }

    gt_free(temp);
    bn_free(coef);
}

/* dec_node_naive: giải mã nút policy */
void dec_node_naive(gt_t r, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub) {
    if (p->children->len == 0) {
        dec_leaf_naive(r, p, prv, pub);
        printf("[dec_node_naive] leaf => p->attr='%s', attri=%d\n", p->attr, p->attri);
    } else {
        dec_internal_naive(r, p, prv, pub);
    }
}

void dec_naive(gt_t r, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub) {
    dec_node_naive(r, p, prv, pub);
}

/* ======= bswabe_dec: giải mã ciphertext ======= */
int bswabe_dec(bswabe_pub_t* pub, bswabe_prv_t* prv, bswabe_cph_t* cph, gt_t m) {
    if (!cph) {
        fprintf(stderr, "[DEBUG] cph is NULL\n");
        return 0;
    }
    if (!cph->p) {
        fprintf(stderr, "[DEBUG] cph->p is NULL\n");
        return 0;
    }
    if (!prv) {
        fprintf(stderr, "[DEBUG] prv is NULL\n");
        return 0;
    }
   // Check if the attributes in the private key satisfy the policy in the ciphertext
   check_sat(cph->p, prv);
   if (!cph->p || !prv || !cph->p->satisfiable) {
       fprintf(stderr, "ERROR: Attributes in private key do not satisfy the policy.\n");
       return 0;
   }
   if (!cph || !cph->p || !prv) {
    fprintf(stderr, "[DEBUG] One or more NULLs: cph=%p, p=%p, prv=%p\n", cph, cph ? cph->p : NULL, prv);
    return 0;
   }

   // Compute the minimum number of leaves required to satisfy the policy
   pick_sat_min_leaves(cph->p, prv);

   // Initialize GT element F for intermediate computation
   gt_t F;
   gt_new(F);

   // Perform decryption using the policy tree
   dec_naive(F, cph->p, prv, pub);

   // Debug print F before multiplying
   printf("[core][dec] F before multiply:\n");
   {
       int size = gt_size_bin(F, 1);
       uint8_t* buf = malloc(size);
       if (!buf) {
           fprintf(stderr, "Memory allocation failed while printing F\n");
           exit(1);
       }
       gt_write_bin(buf, size, F, 1);
       for (int i = 0; i < size; i++) {
           printf("%02x", buf[i]);
       }
       printf("\n");
       free(buf);
   }

   // Normalize F
   gt_norm(F);

   // Debug print F after normalization
   uint8_t buf[512];
   int len = gt_size_bin(F, 1);
   gt_write_bin(buf, len, F, 1);
   printf("[core][dec] F normalized:\n");
   for (int i = 0; i < len; i++) {
       printf("%02x", buf[i]);
   }
   printf("\n");

   // Compute the final message m = cph->cs / F
   gt_inv(F, F);            // Tính nghịch đảo của F
   gt_mul(m, cph->cs, F);   // Tính m = cph->cs / F
   gt_norm(m);

   // Debug print the decrypted message
   {
       int size = gt_size_bin(m, 1);
       uint8_t* buf = malloc(size);
       if (!buf) {
           fprintf(stderr, "Memory allocation failed in bswabe_dec() debug print\n");
           exit(1);
       }
       gt_write_bin(buf, size, m, 1);
       printf("[core][dec] m = ");
       for (int i = 0; i < size; i++) {
           printf("%02x", buf[i]);
       }
       printf("\n");
       free(buf);
   }

   // Free the intermediate GT element
   gt_free(F);

   return 1;
}

/* ======= debug_cph_cs: in giá trị của cph->cs ======= */
void debug_cph_cs(bswabe_cph_t* cph) {
    printf("[core][dec] cph->cs = ");
    uint8_t buf[gt_size_bin(cph->cs, 1)];
    gt_write_bin(buf, sizeof(buf), cph->cs, 1);
    for (int i = 0; i < sizeof(buf); i++)
        printf("%02x", buf[i]);
    printf("\n");
}

/* ======= normalize_attr: chuẩn hóa thuộc tính ======= */
void normalize_attr(char* dst, const char* src) {
    int len = strlen(src);
    int i = 0, j = 0;

    // Bỏ khoảng trắng đầu
    while (i < len && isspace(src[i])) i++;

    // Copy và bỏ ký tự newline, null trong giữa
    while (i < len && src[i] != '\0') {
        if (src[i] != '\n' && src[i] != '\r') {
            dst[j++] = src[i];
        }
        i++;
    }

    // Bỏ khoảng trắng cuối
    while (j > 0 && isspace(dst[j - 1])) j--;

    dst[j] = '\0'; // Kết thúc chuỗi
}
