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
 #include "common.h"     
 #include <relic/relic.h>
 #include <glib.h>
 #include <stdlib.h>
 #include <string.h>
 #include <stdarg.h>
 #include <stdio.h>
 
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

        // Map attribute to G1 using RELIC's ep_map
        g1_t h_attr;
        g1_null(h_attr); g1_new(h_attr);

        uint8_t* attr_bytes = (uint8_t*)p->attr;
        size_t attr_len = strlen(p->attr);
        ep_map(h_attr, attr_bytes, attr_len);

        // Debug: Print the mapped attribute in G1
        int size = g1_size_bin(h_attr, 1);
        uint8_t* buf = malloc(size);
        g1_write_bin(buf, size, h_attr, 1);
        printf("DEBUG fill_policy: Mapped attribute '%s' in G1: ", p->attr);
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
        printf("DEBUG fill_policy: Mapped attribute '%s' in G2: ", p->attr);
        for (int j = 0; j < size; j++) {
            printf("%02x", buf[j]);
        }
        printf("\n");
        free(buf);

        // Debug: Print p->c and p->cp
        size = g1_size_bin(p->c, 1);
        buf = malloc(size);
        g1_write_bin(buf, size, p->c, 1);
        printf("DEBUG fill_policy: p->c for '%s': ", p->attr);
        for (int j = 0; j < size; j++) {
            printf("%02x", buf[j]);
        }
        printf("\n");
        free(buf);

        size = g2_size_bin(p->cp, 1);
        buf = malloc(size);
        g2_write_bin(buf, size, p->cp, 1);
        printf("DEBUG fill_policy: p->cp for '%s': ", p->attr);
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
 
 /* ======= check_sat: duyệt cây policy để đánh dấu các nút thỏa mãn ======= */
void check_sat(bswabe_policy_t* p, bswabe_prv_t* prv) {
    if (p->children->len == 0) {
        // Nút lá
        p->satisfiable = 0;
        for (int i = 0; i < prv->comps->len; i++) {
            bswabe_prv_comp_t* comp = &g_array_index(prv->comps, bswabe_prv_comp_t, i);
            // Debug: In ra giá trị so sánh thuộc tính
            printf("[check_sat] leaf: policy_attr='%s', key_attr='%s'\n", p->attr, comp->attr);
            if (comp->attr && strcmp(comp->attr, p->attr) == 0) {
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

/* Hàm so sánh dùng cho qsort */
int compare_ints(const void *a, const void *b) {
    int int_a = *(const int*)a;
    int int_b = *(const int*)b;
    return int_a - int_b;
}

/* ======= pick_sat_min_leaves: tính số nút lá tối thiểu cần thiết ======= */
void pick_sat_min_leaves(bswabe_policy_t* p, bswabe_prv_t* prv) {
    if(p->children->len == 0) {
        p->min_leaves = p->satisfiable ? 1 : 1000000;
        printf("[pick_sat_min_leaves] leaf '%s' => satisfiable=%d => min_leaves=%d\n",
               p->attr, p->satisfiable, p->min_leaves);
    } else {
        // Đệ quy tính min_leaves cho từng con.
        for (int i = 0; i < p->children->len; i++) {
            bswabe_policy_t* child = g_ptr_array_index(p->children, i);
            pick_sat_min_leaves(child, prv);
        }
        // Thu thập min_leaves của các nút con thỏa mãn.
        int n = p->children->len;
        int *mins = malloc(sizeof(int) * n);
        int count = 0;
        for (int i = 0; i < n; i++) {
            bswabe_policy_t* child = g_ptr_array_index(p->children, i);
            if(child->satisfiable) {
                mins[count++] = child->min_leaves;
            }
        }
        if(count < p->k) {
            // không đủ nút con thỏa mãn, đặt min_leaves là INF.
            p->min_leaves = 1000000;
        } else {
            // Sắp xếp các giá trị min_leaves và cộng tổng của k giá trị nhỏ nhất.
            qsort(mins, count, sizeof(int), compare_ints);
            int sum = 0;
            for (int i = 0; i < p->k; i++) {
                sum += mins[i];
            }
            p->min_leaves = sum;
        }
        free(mins);
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
 
 /* dec_leaf_naive: r = e(p->c, c->d) / e(c->dp, p->cp) */
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
 
 /* dec_node_naive: nội suy Lagrange */
 void dec_node_naive(gt_t r, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub) {
     if(p->children->len == 0) {
         dec_leaf_naive(r, p, prv, pub);
         printf("[dec_node_naive] leaf => p->attr='%s', attri=%d\n", p->attr, p->attri);
     } else {
         gt_t temp;
         bn_t coef;
         gt_new(temp);
         bn_new(coef);
         gt_set_unity(r);

         // In mảng p->satl trước vòng lặp
         printf("[dec_node_naive] p->satl contents: ");
         for (int idx = 0; idx < p->satl->len; idx++) {
             printf("%d ", g_array_index(p->satl, int, idx));
         }
         printf("\n");

         printf("[dec_node_naive] internal => p->k=%d, satl->len=%d\n", p->k, p->satl->len);

         for (int i = 0; i < p->satl->len; i++) {
             int idx = g_array_index(p->satl, int, i) - 1;
             dec_node_naive(temp, g_ptr_array_index(p->children, idx), prv, pub);
             lagrange_coef(coef, p->satl, g_array_index(p->satl, int, i), pub->order);

             // In hệ số lambda (Lagrange coefficient)
             {
                 char coef_str[256];
                 bn_write_str(coef_str, 256, coef, 16); // Convert to hexadecimal string
                 printf("[dec_node_naive] Lambda coefficient for index %d: %s\n", g_array_index(p->satl, int, i), coef_str);
             }

             gt_exp(temp, temp, coef);

             // In giá trị intermediate của temp sau exponentiation
             {
                 int size = gt_size_bin(temp, 1);
                 uint8_t* buf = malloc(size);
                 if (buf == NULL) {
                     fprintf(stderr, "Memory allocation failed for debug buffer in dec_node_naive.\n");
                     exit(1);
                 }
                 gt_write_bin(buf, size, temp, 1);
                 printf("[dec_node_naive] Intermediate temp after exponentiation: ");
                 for (int j = 0; j < size; j++) {
                     printf("%02x", buf[j]);
                 }
                 printf("\n");
                 free(buf);
             }

             gt_mul(r, r, temp);
             gt_norm(r); // Corrected normalization
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

    // Tính F = e(g_hat_alpha,g)^{-s} 
    gt_t F;
    gt_new(F);
    dec_node_naive(F, cph->p, prv, pub);

    // Chuẩn hoá F trước khi in
    gt_norm(F);

    // In giá trị của F
    int buf_len = gt_size_bin(F, 1);
    uint8_t* buf = malloc(buf_len);
    gt_write_bin(buf, buf_len, F, 1);
    printf("Value of F: ");
    for (int i = 0; i < buf_len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
    free(buf);

    // m = (cs) * F = ( M * e(g_hat_alpha,g)^s ) * e(g_hat_alpha,g)^{-s} = M
    gt_mul(m, cph->cs, F);

    // Chuẩn hoá m trước khi in
    gt_norm(m);

    // In giá trị của m
    buf_len = gt_size_bin(m, 1);
    buf = malloc(buf_len);
    gt_write_bin(buf, buf_len, m, 1);
    printf("Value of m (dec): ");
    for (int i = 0; i < buf_len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
    free(buf);

    gt_free(F);

    // Chuẩn hoá GT element
    gt_norm(m);

    return 1;
}
 
 /* ======= bswabe_enc: mã hóa ======= */
 bswabe_cph_t* bswabe_enc(bswabe_pub_t* pub, gt_t m, bn_t s, char* policy) {
    // Allocate memory for the ciphertext structure
    bswabe_cph_t* cph = malloc(sizeof(bswabe_cph_t));
    if (!cph) {
        fprintf(stderr, "ERROR: Memory allocation failed for bswabe_cph_t.\n");
        return NULL;
    }

    // Debug: Print the value of m
    int buf_len = gt_size_bin(m, 1);
    uint8_t* buf = malloc(buf_len);
    if (!buf) {
        fprintf(stderr, "Memory allocation failed for debug buffer.\n");
        free(cph);
        return NULL;
    }
    gt_write_bin(buf, buf_len, m, 1);
    printf("Value of m (enc): ");
    for (int i = 0; i < buf_len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
    free(buf);

    // Compute cs = m * e(pub->g_hat_alpha, s)
    gt_null(cph->cs);
    gt_new(cph->cs);
    gt_t tmp;
    gt_null(tmp);
    gt_new(tmp);
    gt_exp(tmp, pub->g_hat_alpha, s); // tmp = e(g_hat_alpha, s)
    gt_mul(cph->cs, m, tmp);          // cph->cs = m * tmp
    gt_free(tmp);

    // Compute c = h^s
    g1_null(cph->c);
    g1_new(cph->c);
    g1_mul(cph->c, pub->h, s);        // cph->c = h^s

    // Parse the policy string into a policy tree
    bswabe_policy_t* root = parse_policy_postfix(policy);
    if (!root) {
        fprintf(stderr, "ERROR: Failed to parse policy string.\n");
        free(cph);
        return NULL;
    }
    cph->p = root;
    cph->policy = strdup(policy); // Save the original policy string

    // Share the secret s according to the policy tree
    fill_policy(cph->p, pub, s);

    // If s is no longer needed, free it
    bn_free(s);

    return cph;
}

