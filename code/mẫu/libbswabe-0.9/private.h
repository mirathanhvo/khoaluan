#ifndef PRIVATE_H
#define PRIVATE_H

#include "bswabe.h"

/* Thành phần khóa bí mật */
typedef struct {
    char* attr;  /* Chuỗi thuộc tính */
    g2_t d;      /* Thành phần G_2 */
    g1_t dp;     /* Thành phần G_1 */  // 
    int used;    /* Cờ đánh dấu sử dụng */
    g1_t z;      /* Thành phần G_1 */
    g1_t zp;     /* Thành phần G_1 */
} bswabe_prv_comp_t;

/* Cấu trúc khóa bí mật */
struct bswabe_prv_s {
    g2_t d;   /* G_2 */
    GArray* comps; /* Mảng động chứa các thành phần */
    int comps_len;  /* Số lượng thành phần trong comps */
};

/* Định nghĩa đa thức sử dụng trong scheme */
typedef struct {
    int deg;
    bn_t* coef; /* Mảng hệ số bậc deg + 1 */
} bswabe_polynomial_t;

/* Cấu trúc chính sách truy cập */
typedef struct bswabe_policy_s {
    int k;                    /* Ngưỡng k-out-of-n */
    char* attr;                /* Thuộc tính nếu là lá */
    g1_t c, cp;                /* Hệ số dùng trong mã hóa */
    struct bswabe_policy_s** children; /* Mảng con */
    int children_len;
    bswabe_polynomial_t* q;
    int satisfiable;
    int min_leaves;
    int attri;
    int* satl; /* Mảng thuộc tính thỏa mãn */
    int satl_len;
} bswabe_policy_t;

/* Cấu trúc ciphertext */
struct bswabe_cph_s {
    gt_t cs; /* G_T */
    g1_t c;  /* G_1 */
    bswabe_policy_t* p;
};

/* Hàm cấp phát bộ nhớ cho `bswabe_prv_t` */
static inline void bswabe_prv_init(bswabe_prv_t* prv) {
    prv->comps = g_array_new(FALSE, TRUE, sizeof(bswabe_prv_comp_t));
    if (!prv->comps) {
        fprintf(stderr, "Memory allocation failed in bswabe_prv_init()\n");
        exit(1);
    }
    prv->comps_len = 0;
}

/* Hàm cấp phát bộ nhớ cho `bswabe_policy_t` */
static inline bswabe_policy_t* bswabe_policy_new(int children_len) {
    bswabe_policy_t* p = malloc(sizeof(bswabe_policy_t));
    if (!p) {
        fprintf(stderr, "Memory allocation failed in bswabe_policy_new()\n");
        exit(1);
    }
    p->children = malloc(sizeof(bswabe_policy_t*) * children_len);
    if (!p->children) {
        fprintf(stderr, "Memory allocation failed in bswabe_policy_new()\n");
        free(p);
        exit(1);
    }
    p->children_len = children_len;
    return p;
}

#endif /* PRIVATE_H */
