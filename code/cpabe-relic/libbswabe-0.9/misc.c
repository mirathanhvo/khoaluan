#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <relic.h>

#include "bswabe.h"
#include "private.h"

void serialize_uint32(GByteArray* b, uint32_t k) {
    for (int i = 3; i >= 0; i--) {
        guint8 byte = (k >> (i * 8)) & 0xFF;
        g_byte_array_append(b, &byte, 1);
    }
}

uint32_t unserialize_uint32(GByteArray* b, int* offset) {
    uint32_t r = 0;
    for (int i = 3; i >= 0; i--) {
        r |= (b->data[(*offset)++]) << (i * 8);
    }
    return r;
}

void serialize_bn(GByteArray* b, bn_t n) {
    uint32_t len = bn_size_bin(n);  // Lấy kích thước nhị phân của bn
    serialize_uint32(b, len);  // Serialize chiều dài
    unsigned char* buf = malloc(len);  // Cấp phát bộ nhớ đủ lớn
    if (buf == NULL) {
        fprintf(stderr, "ERROR: Memory allocation failed in serialize_bn()\n");
        exit(1);  // Kiểm tra lỗi cấp phát
    }
    bn_write_bin(buf, len, n);  // Viết dữ liệu vào buffer
    g_byte_array_append(b, buf, len);  // Ghi buffer vào GByteArray
    free(buf);  // Giải phóng bộ nhớ
}

void unserialize_bn(GByteArray* b, int* offset, bn_t n) {
    uint32_t len = unserialize_uint32(b, offset);
    unsigned char* buf = malloc(len);
    memcpy(buf, b->data + *offset, len);
    *offset += len;
    bn_read_bin(n, buf, len);
    free(buf);
}
void serialize_string(GByteArray* b, const char* s) {
    g_byte_array_append(b, (guint8*)s, strlen(s) + 1);
}

char* unserialize_string(GByteArray* b, int* offset) {
    GString* s = g_string_sized_new(32);
    while (1) {
        char c = b->data[(*offset)++];
        if (c == '\0') break;
        g_string_append_c(s, c);
    }
    char* result = s->str;
    g_string_free(s, FALSE);
    return result;
}

/* Serialize G1 */
void serialize_g1(GByteArray* b, g1_t e) {
    uint32_t len = g1_size_bin(e, 1);
    serialize_uint32(b, len);
    unsigned char* buf = malloc(len);
    if (!buf) {
        fprintf(stderr, "ERROR: Memory allocation failed in serialize_g1().\n");
        exit(1);
    }
    g1_write_bin(buf, len, e, 1);
    g_byte_array_append(b, buf, len);
    free(buf);
}

void unserialize_g1(GByteArray* b, int* offset, g1_t e) {
    uint32_t len = unserialize_uint32(b, offset);
    if (*offset + len > b->len) {
        fprintf(stderr, "ERROR: Buffer too small in unserialize_g1().\n");
        exit(1);
    }
    unsigned char* buf = malloc(len);
    if (!buf) {
        fprintf(stderr, "ERROR: Memory allocation failed in unserialize_g1().\n");
        exit(1);
    }
    memcpy(buf, b->data + *offset, len);
    *offset += len;
    g1_read_bin(e, buf, len);
    free(buf);
}

/* Serialize G2 */
void serialize_g2(GByteArray* b, g2_t e) {
    uint32_t len = g2_size_bin(e, 1);
    serialize_uint32(b, len);
    unsigned char* buf = malloc(len);
    if (!buf) {
        fprintf(stderr, "ERROR: Memory allocation failed in serialize_g2().\n");
        exit(1);
    }
    g2_write_bin(buf, len, e, 1);
    g_byte_array_append(b, buf, len);
    free(buf);
}

void unserialize_g2(GByteArray* b, int* offset, g2_t e) {
    uint32_t len = unserialize_uint32(b, offset);
    if (*offset + len > b->len) {
        fprintf(stderr, "ERROR: Buffer too small in unserialize_g2().\n");
        exit(1);
    }
    unsigned char* buf = malloc(len);
    if (!buf) {
        fprintf(stderr, "ERROR: Memory allocation failed in unserialize_g2().\n");
        exit(1);
    }
    memcpy(buf, b->data + *offset, len);
    *offset += len;
    g2_read_bin(e, buf, len);
    free(buf);
}

/* Serialize GT */
void serialize_gt(GByteArray* b, gt_t e) {
    uint32_t len = gt_size_bin(e, 1);
    serialize_uint32(b, len);
    unsigned char* buf = malloc(len);
    if (!buf) {
        fprintf(stderr, "ERROR: Memory allocation failed in serialize_gt().\n");
        exit(1);
    }
    gt_write_bin(buf, len, e, 1);
    g_byte_array_append(b, buf, len);
    free(buf);
}

void unserialize_gt(GByteArray* b, int* offset, gt_t e) {
    uint32_t len = unserialize_uint32(b, offset);
    if (*offset + len > b->len) {
        fprintf(stderr, "ERROR: Buffer too small in unserialize_gt().\n");
        exit(1);
    }
    unsigned char* buf = malloc(len);
    if (!buf) {
        fprintf(stderr, "ERROR: Memory allocation failed in unserialize_gt().\n");
        exit(1);
    }
    memcpy(buf, b->data + *offset, len);
    *offset += len;
    gt_read_bin(e, buf, len);
    free(buf);
}


// Hàm serialize public key: chuyển đối tượng bswabe_pub_t thành một GByteArray
GByteArray* bswabe_pub_serialize(bswabe_pub_t* pub) {
    GByteArray* buf = g_byte_array_new();
    // Serialize theo thứ tự: g, gp, g_hat_alpha, h.
    serialize_g1(buf, pub->g);
    serialize_g2(buf, pub->gp);
    serialize_gt(buf, pub->g_hat_alpha);
    serialize_g1(buf, pub->h);
    serialize_bn(buf, pub->order);

    return buf;
}

// Hàm unserialize public key: đọc từ GByteArray và khởi tạo một đối tượng bswabe_pub_t.
bswabe_pub_t* bswabe_pub_unserialize(GByteArray* buf, int free_flag) {
    int offset = 0;
    bswabe_pub_t* pub = malloc(sizeof(bswabe_pub_t));
    if (!pub) {
        fprintf(stderr, "Error: Failed to unserialize public key.\n");
        return NULL;
    }

    // Khởi tạo các thành phần của public key
    g1_null(pub->g);
    g1_new(pub->g);

    g2_null(pub->gp);
    g2_new(pub->gp);

    gt_null(pub->g_hat_alpha);
    gt_new(pub->g_hat_alpha);

    g1_null(pub->h);
    g1_new(pub->h);

    // Giả sử thứ tự serialize là: g, gp, g_hat_alpha, h.
    unserialize_g1(buf, &offset, pub->g);
    unserialize_g2(buf, &offset, pub->gp);
    unserialize_gt(buf, &offset, pub->g_hat_alpha);
    unserialize_g1(buf, &offset, pub->h);

    // Unserialize trường order
    bn_null(pub->order);
    bn_new(pub->order);
    unserialize_bn(buf, &offset, pub->order);
    
    if (free_flag) {
        g_byte_array_free(buf, TRUE);
    }
    return pub;
}


GByteArray* bswabe_msk_serialize(bswabe_msk_t* msk) {
    GByteArray* b = g_byte_array_new();
    serialize_g2(b, msk->g_alpha);  
    serialize_bn(b, msk->beta);
    return b;
}

bswabe_msk_t* bswabe_msk_unserialize(bswabe_pub_t* pub, GByteArray* b, int free) {
    bswabe_msk_t* msk = malloc(sizeof(bswabe_msk_t));
    int offset = 0;
    g2_new(msk->g_alpha);
    unserialize_g2(b, &offset, msk->g_alpha);  
    bn_null(msk->beta);
    bn_new(msk->beta);
    unserialize_bn(b, &offset, msk->beta);
    if (free) g_byte_array_free(b, 1);
    return msk;
}


// Hàm serialize private key: chuyển đối tượng bswabe_prv_t thành một GByteArray
GByteArray* bswabe_prv_serialize(bswabe_prv_t* prv) {
    GByteArray* b = g_byte_array_new();

    // 1) Ghi phần tử d (thuộc G2)
    serialize_g2(b, prv->d);

    // 2) Ghi số lượng components
    serialize_uint32(b, prv->comps->len);

    // 3) Ghi từng component
    for (int i = 0; i < prv->comps->len; i++) {
        bswabe_prv_comp_t* c = &g_array_index(prv->comps, bswabe_prv_comp_t, i);

        // 3.1) Ghi tên thuộc tính (string null-terminated)
        serialize_string(b, c->attr);

        // 3.2) Ghi phần tử d (G2) và dp (G1)
        serialize_g2(b, c->d);
        serialize_g1(b, c->dp);
    }

    return b;
}

// Hàm unserialize private key: đọc từ GByteArray và khởi tạo một đối tượng bswabe_prv_t.
bswabe_prv_t* bswabe_prv_unserialize(bswabe_pub_t* pub, GByteArray* b, int free_buf) {
    int offset = 0;

    bswabe_prv_t* prv = malloc(sizeof(bswabe_prv_t));
    if (!prv) {
        fprintf(stderr, "Memory allocation failed in bswabe_prv_unserialize\n");
        return NULL;
    }

    // 1) Đọc phần tử d
    g2_null(prv->d); g2_new(prv->d);
    unserialize_g2(b, &offset, prv->d);

    // 2) Đọc số lượng components
    uint32_t count = unserialize_uint32(b, &offset);

    // 3) Đọc từng component
    prv->comps = g_array_new(FALSE, TRUE, sizeof(bswabe_prv_comp_t));
    for (uint32_t i = 0; i < count; i++) {
        bswabe_prv_comp_t c;

        // 3.1) Thuộc tính (attr)
        c.attr = unserialize_string(b, &offset);

        // 3.2) d ∈ G2
        g2_null(c.d); g2_new(c.d);
        unserialize_g2(b, &offset, c.d);

        // 3.3) dp ∈ G1
        g1_null(c.dp); g1_new(c.dp);
        unserialize_g1(b, &offset, c.dp);

        g_array_append_val(prv->comps, c);
    }

    prv->comps_len = count;

    if (free_buf) g_byte_array_free(b, TRUE);
    return prv;
}

void serialize_policy(GByteArray *b, bswabe_policy_t *p) {
    // Serialize ngưỡng k
    serialize_uint32(b, (uint32_t)p->k);

    // Serialize số lượng con
    uint32_t num_children = p->children->len;
    serialize_uint32(b, num_children);

    // Nếu là nút lá (leaf) thì num_children == 0
    if (num_children == 0) {
        // Serialize chuỗi attribute (nếu có)
        if (p->attr != NULL) {
            uint32_t attr_len = (uint32_t)strlen(p->attr);
            serialize_uint32(b, attr_len);
            g_byte_array_append(b, (const guint8 *)p->attr, attr_len);
        } else {
            serialize_uint32(b, 0); // Ghi độ dài 0 nếu không có attribute
        }

        // Serialize p->c (G1)
        if (p->c) {
            serialize_g1(b, p->c);
        } else {
            fprintf(stderr, "ERROR: Missing G1 element in leaf node.\n");
            exit(1);
        }

        // Serialize p->cp (G2)
        if (p->cp) {
            serialize_g2(b, p->cp);
        } else {
            fprintf(stderr, "ERROR: Missing G2 element in leaf node.\n");
            exit(1);
        }
    } else {
        // Nếu là nút nội, không có attribute và các phần tử tính toán
        for (int i = 0; i < num_children; i++) {
            bswabe_policy_t *child = g_ptr_array_index(p->children, i);
            serialize_policy(b, child); // Đệ quy serialize các nút con
        }
    }
}

bswabe_policy_t* unserialize_policy(bswabe_pub_t *pub, GByteArray *b, int *offset) {
    // Cấp phát bộ nhớ cho một nút policy mới
    bswabe_policy_t *p = malloc(sizeof(bswabe_policy_t));
    if (!p) {
        fprintf(stderr, "Memory allocation failed in unserialize_policy()\n");
        exit(1);
    }
    p->children = g_ptr_array_new();
    p->q = NULL; // Không sử dụng đa thức q
    p->attr = NULL; // Khởi tạo mặc định
    p->satl = g_array_new(FALSE, FALSE, sizeof(int));
    
    // Đọc ngưỡng k
    p->k = (int) unserialize_uint32(b, offset);
    // Đọc số lượng children
    uint32_t num_children = unserialize_uint32(b, offset);
    
    if (num_children == 0) {
        // Đây là nút lá, nên đọc chuỗi attribute
        uint32_t attr_len = unserialize_uint32(b, offset);
        if (attr_len > 0) {
            p->attr = malloc(attr_len + 1);
            if (!p->attr) {
                fprintf(stderr, "Memory allocation failed in unserialize_policy (attr)\n");
                exit(1);
            }
            memcpy(p->attr, b->data + *offset, attr_len);
            p->attr[attr_len] = '\0';
            *offset += attr_len;

            // Chuẩn hóa thuộc tính
            char norm_attr[256];
            normalize_attr(norm_attr, p->attr);
            free(p->attr);
            p->attr = strdup(norm_attr);
        }
        // Khởi tạo và unserialize p->c (G1)
        g1_null(p->c);
        g1_new(p->c);
        unserialize_g1(b, offset, p->c);
        // Khởi tạo và unserialize p->cp (G2)
        g2_null(p->cp);
        g2_new(p->cp);
        unserialize_g2(b, offset, p->cp);
    } else {
        // Nếu là nút nội, không có attribute và các phần tử tính toán của lá.
        // Đệ quy unserialize từng nút con
        for (int i = 0; i < num_children; i++) {
            bswabe_policy_t *child = unserialize_policy(pub, b, offset);
            g_ptr_array_add(p->children, child);
        }
    }
    return p;
}


GByteArray* bswabe_cph_serialize(bswabe_cph_t* cph) {
    GByteArray* buf = g_byte_array_new();
    serialize_gt(buf, cph->cs);
    serialize_g1(buf, cph->c);
    serialize_policy(buf, cph->p);
    return buf;
}

bswabe_cph_t* bswabe_cph_unserialize(bswabe_pub_t* pub, GByteArray* buf, int free_flag) {
    int offset = 0;
    bswabe_cph_t* cph = malloc(sizeof(bswabe_cph_t));
    if (!cph) return NULL;

    gt_null(cph->cs); gt_new(cph->cs);
    g1_null(cph->c);  g1_new(cph->c);

    unserialize_gt(buf, &offset, cph->cs);
    unserialize_g1(buf, &offset, cph->c);
    cph->p = unserialize_policy(pub, buf, &offset);

    if (free_flag)
        g_byte_array_free(buf, TRUE);

    return cph;
}

void bswabe_pub_free(bswabe_pub_t* pub) {
    g1_free(pub->g);
    g1_free(pub->h);
    g2_free(pub->gp);
    gt_free(pub->g_hat_alpha);
    free(pub);
}

void bswabe_msk_free(bswabe_msk_t* msk) {
    bn_free(msk->beta);
    g2_free(msk->g_alpha);
    free(msk);
}


void bswabe_prv_free(bswabe_prv_t* prv) {
    if (!prv) return;

    g2_free(prv->d);

    if (prv->comps) {
        for (int i = 0; i < prv->comps->len; i++) {
            bswabe_prv_comp_t* comp = &g_array_index(prv->comps, bswabe_prv_comp_t, i);

            if (comp->attr) free(comp->attr);
            g2_free(comp->d);
            g1_free(comp->dp);
        }

        g_array_free(prv->comps, TRUE);
    }

    free(prv);
}

void bswabe_policy_free(bswabe_policy_t* p) {
    if (!p) return;

    if (p->attr) {
        free(p->attr);
        g1_free(p->c);
        g2_free(p->cp);
    }

    if (p->q) {
        for (int i = 0; i <= p->q->deg; i++) {
            bn_free(p->q->coef[i]);
        }
        free(p->q->coef);
        free(p->q);
    }

    if (p->satl) g_array_free(p->satl, TRUE);

    if (p->children) {
        for (int i = 0; i < p->children->len; i++) {
            bswabe_policy_free(g_ptr_array_index(p->children, i));
        }
        g_ptr_array_free(p->children, TRUE);
    }

    free(p);
}

void bswabe_cph_free(bswabe_cph_t* cph) {
    if (!cph) return;

    gt_free(cph->cs);
    g1_free(cph->c);
    bswabe_policy_free(cph->p);  // gọi hàm giải phóng policy
    free(cph);
}


