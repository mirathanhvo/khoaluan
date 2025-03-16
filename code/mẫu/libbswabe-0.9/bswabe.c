/*
 * bswabe.c
 *
 * Các hàm CP-ABE mã hóa và giải mã sử dụng thư viện RELIC.
 * Lưu ý: Các hàm setup và keygen đã được triển khai ở core.c.
 *
 * Phiên bản đã chuyển đổi khỏi PBC (element_t...) sang RELIC (bn_t, g1_t, g2_t, gt_t...).
 */

 #include "bswabe.h"
 #include "private.h"
 #include "common.h"        // <-- Dùng prototype cho raise_error(), element_from_string()... nếu cần
 #include <relic/relic.h>
 #include <glib.h>
 #include <stdlib.h>
 #include <string.h>
 #include <stdarg.h>
 #include <stdio.h>
 
 /* 
    ĐÃ XÓA: 
    - char last_error[256];
    - char* bswabe_error();
    - void raise_error(...);
    - void element_from_string(...);
    - void element_from_string_g2(...);
    vì chúng đã được định nghĩa trong common.c
 */
 
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
 
         // map attr -> G1
         g1_t h_attr;
         g1_new(h_attr);
         // gọi element_from_string() đã có trong common.c
         element_from_string(h_attr, p->attr);
 
         g1_mul(p->c, pub->g, p->q->coef[0]);
 
         // map attr -> G2
         g2_t h2_attr;
         g2_new(h2_attr);
         element_from_string_g2(h2_attr, p->attr);
         g2_mul(p->cp, h2_attr, p->q->coef[0]);
 
         g1_free(h_attr);
         g2_free(h2_attr);
     } else {
         bn_t r, t;
         bn_null(r); bn_new(r);
         bn_null(t); bn_new(t);
 
         for(int i = 0; i < (int)p->children->len; i++) {
             bn_set_dig(r, i+1);
             eval_poly(t, p->q, r, pub->order);
             fill_policy(g_ptr_array_index(p->children, i), pub, t);
         }
         bn_free(r);
         bn_free(t);
     }
 }
 
 /* ======= check_sat, pick_sat_min_leaves ======= */
 void check_sat(bswabe_policy_t* p, bswabe_prv_t* prv) {
     // ...
 }
 
 void pick_sat_min_leaves(bswabe_policy_t* p, bswabe_prv_t* prv) {
     // ...
 }
 
 /* ======= lagrange_coef (trong Zr) ======= */
 void lagrange_coef(bn_t r, GArray* s, int i, bn_t order) {
     bn_t t;
     bn_null(t); bn_new(t);
     bn_set_dig(r, 1);
 
     for(int idx = 0; idx < (int)s->len; idx++){
         int jj = g_array_index(s, int, idx);
         if(jj == i) continue;
 
         bn_set_dig(t, (jj > 0) ? jj : -jj);
         if(jj > 0) bn_neg(t, t);
         bn_mod(t, t, order);
         bn_mul(r, r, t);
         bn_mod(r, r, order);
 
         bn_set_dig(t, (i - jj) < 0 ? -(i-jj) : (i-jj));
         if((i-jj) < 0) bn_neg(t, t);
         bn_mod(t, t, order);
         bn_mod_inv(t, t, order);
         bn_mul(r, r, t);
         bn_mod(r, r, order);
     }
     bn_free(t);
 }
 
 /* dec_leaf_naive: r = e(p->c, c->d) / e(c->dp, p->cp) */
 void dec_leaf_naive(gt_t r, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub) {
     bswabe_prv_comp_t* c = &(g_array_index(prv->comps, bswabe_prv_comp_t, p->attri));
     gt_t A, B;
     gt_new(A); gt_new(B);
 
     pc_map(A, p->c, c->d);
     pc_map(B, c->dp, p->cp);
     gt_inv(B, B);
     gt_mul(r, A, B);
 
     gt_free(A); gt_free(B);
 }
 
 /* dec_node_naive: nội suy Lagrange */
 void dec_node_naive(gt_t r, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub) {
     if(p->children->len == 0) {
         dec_leaf_naive(r, p, prv, pub);
     } else {
         gt_t temp;
         bn_t coef;
         gt_new(temp);
         bn_new(coef);
         gt_set_unity(r);
 
         for(int i = 0; i < p->satl->len; i++){
             int idx = g_array_index(p->satl, int, i) - 1;
             dec_node_naive(temp, g_ptr_array_index(p->children, idx), prv, pub);
             lagrange_coef(coef, p->satl, g_array_index(p->satl, int, i), pub->order);
             gt_exp(temp, temp, coef);
             gt_mul(r, r, temp);
         }
         gt_free(temp);
         bn_free(coef);
     }
 }
 
 /* ======= bswabe_dec: giải mã ciphertext ======= */
 int bswabe_dec(bswabe_pub_t* pub, bswabe_prv_t* prv, bswabe_cph_t* cph, gt_t m) {
    check_sat(cph->p, prv);
    if (!cph->p) {
        fprintf(stderr, "ERROR: Ciphertext policy tree is NULL.\n");
        return 0;
    }
    if (!prv) {
        fprintf(stderr, "ERROR: Private key is NULL.\n");
        return 0;
    }
    if (!cph->p->satisfiable) {
        fprintf(stderr, "ERROR: Attributes in private key do not satisfy the policy.\n");
        return 0;
    }
    pick_sat_min_leaves(cph->p, prv);

    gt_t F;
    gt_new(F);
    dec_node_naive(F, cph->p, prv, pub);

    gt_mul(m, cph->cs, F);

    gt_t tmp;
    gt_new(tmp);
    pc_map(tmp, cph->c, prv->d);
    gt_inv(tmp, tmp);
    gt_mul(m, m, tmp);

    gt_free(F);
    gt_free(tmp);
    return 1;
 }
 
 /* ======= bswabe_enc: mã hóa ======= */
 bswabe_cph_t* bswabe_enc(bswabe_pub_t* pub, gt_t m, char* policy) {
     bswabe_cph_t* cph = malloc(sizeof(bswabe_cph_t));
     if(!cph) return NULL;
 
     bn_t s;
     bn_null(s); bn_new(s);
     bn_rand_mod(s, pub->order);
 
     gt_new(cph->cs);
     gt_t tmp;
     gt_new(tmp);
     gt_exp(tmp, pub->g_hat_alpha, s);
     gt_mul(cph->cs, tmp, m);
     gt_free(tmp);
 
     g1_new(cph->c);
     g1_mul(cph->c, pub->h, s);
 
     // parse policy -> fill
     bswabe_policy_t* root = parse_policy_postfix(policy);
     if(!root) {
         free(cph);
         bn_free(s);
         return NULL;
     }
     cph->p = root;
     fill_policy(cph->p, pub, s);
 
     bn_free(s);
     return cph;
 }
