#ifndef PRIVATE_H
#define PRIVATE_H

#include <glib.h>
#include <relic/relic.h>
#include <common.h>
/* Thành phần khóa bí mật */
typedef struct {
    char* attr;  /* Chuỗi thuộc tính */
    g2_t d;      /* Thành phần G_2 */
    g1_t dp;     /* Thành phần G_1 */
    int used;    /* Cờ đánh dấu sử dụng */
    g2_t z;      /* Thành phần G_2 */
    g1_t zp;     /* Thành phần G_1 */
} bswabe_prv_comp_t;

/* Cấu trúc khóa bí mật */
typedef struct bswabe_prv_s {
    g2_t d;   /* G_2 */
    GArray* comps; /* Mảng động chứa các thành phần */
    int comps_len;  /* Số lượng thành phần trong comps */
} bswabe_prv_t;

/* Định nghĩa đa thức sử dụng trong scheme */
typedef struct {
    int deg;
    bn_t* coef; /* Mảng hệ số bậc deg + 1 */
} bswabe_polynomial_t;

/* Cấu trúc chính sách truy cập */
typedef struct bswabe_policy_s {
    int k;               /* Ngưỡng k-out-of-n */
    char* attr;          /* Thuộc tính nếu là lá, hoặc NULL nếu là nút nội */
    GPtrArray* children; /* Sử dụng GPtrArray để quản lý nút con */
    bswabe_polynomial_t* q;
    int satisfiable;
    int min_leaves;
    int attri;
    GArray* satl;        /* Sử dụng GArray để lưu chỉ số các nút thỏa mãn */
    /* Thêm các trường cần thiết cho ciphertext lá: */
    g1_t c;              /* Thành phần trong G1 */
    g2_t cp;             /* Thành phần trong G2 */
} bswabe_policy_t;

/* Cấu trúc ciphertext */
struct bswabe_cph_s {
    gt_t cs;      /* G_T */
    g1_t c;       /* G_1 */
    bswabe_policy_t* p;
    char* policy; /* THÊM: Lưu chuỗi policy gốc dùng khi mã hóa */
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
static inline bswabe_policy_t* bswabe_policy_new(void) {
    bswabe_policy_t* p = malloc(sizeof(bswabe_policy_t));
    if (!p) die("Memory allocation failed in bswabe_policy_new()\n");
    p->children = g_ptr_array_new();
    p->attr = NULL;
    p->k = 0;
    p->q = NULL;
    p->satisfiable = 0;
    p->min_leaves = 0;
    p->attri = -1;
    p->satl = g_array_new(FALSE, FALSE, sizeof(int));
    return p;
}

#endif /* PRIVATE_H */

