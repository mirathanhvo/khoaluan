#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <relic.h>

#include "bswabe.h"
#include "private.h"
#include "../cpabe-0.11/common.h"

void serialize_policy(GByteArray *b, bswabe_policy_t *p);
bswabe_policy_t* unserialize_policy(bswabe_pub_t *pub, GByteArray *b, int *offset);
bswabe_policy_t* parse_policy_postfix(char* s);


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
        die("Memory allocation failed in serialize_bn()");  // Kiểm tra lỗi cấp phát
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

    // In ra kích thước của g và gp
    printf("g size: %ld\n", g1_size_bin(pub->g, 1));
    printf("gp size: %ld\n", g2_size_bin(pub->gp, 1));
    

    if (free_flag) {
        g_byte_array_free(buf, TRUE);
    }
    return pub;
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

// Hàm unserialize private key: đọc từ GByteArray và khởi tạo một đối tượng bswabe_prv_t.
bswabe_prv_t* bswabe_prv_unserialize(bswabe_pub_t* pub, GByteArray* buf, int free_flag) {
    int offset = 0;

    // Cấp phát bswabe_prv_t
    bswabe_prv_t* prv = malloc(sizeof(bswabe_prv_t));
    if (!prv) {
        return NULL;
    }

    // Khởi tạo d
    g2_null(prv->d);
    g2_new(prv->d);

    // Khởi tạo comps
    prv->comps = g_array_new(FALSE, TRUE, sizeof(bswabe_prv_comp_t));
    prv->comps_len = 0;

    // 1) Đọc số thuộc tính n
    if (offset + sizeof(uint32_t) > buf->len) {
        // File quá ngắn, không có uint32_t
        free(prv);
        return NULL;
    }
    uint32_t n;
    memcpy(&n, buf->data + offset, 4);
    offset += 4;

    // 2) Đọc g2 d
    unserialize_g2(buf, &offset, prv->d);

    // 3) Đọc n comp
    for (int i = 0; i < n; i++) {
        bswabe_prv_comp_t comp;
        memset(&comp, 0, sizeof(bswabe_prv_comp_t));

        // comp.attr
        if (offset + 4 > buf->len) {
            // File thiếu dữ liệu
            free(prv);
            return NULL;
        }
        uint32_t attr_len;
        memcpy(&attr_len, buf->data + offset, 4);
        offset += 4;

        if (attr_len > 0) {
            comp.attr = malloc(attr_len + 1);
            memcpy(comp.attr, buf->data + offset, attr_len);
            comp.attr[attr_len] = '\0';
            offset += attr_len;
        } else {
            // attr_len = 0 => comp.attr = NULL
            comp.attr = NULL;
        }

        // comp.d (g2)
        g2_null(comp.d);
        g2_new(comp.d);
        unserialize_g2(buf, &offset, comp.d);

        // comp.dp (g1)
        g1_null(comp.dp);
        g1_new(comp.dp);
        unserialize_g1(buf, &offset, comp.dp);

        // comp.z (g2)
        g2_null(comp.z);
        g2_new(comp.z);
        unserialize_g2(buf, &offset, comp.z);

        // comp.zp (g1)
        g1_null(comp.zp);
        g1_new(comp.zp);
        unserialize_g1(buf, &offset, comp.zp);

        // Thêm comp vào mảng
        g_array_append_val(prv->comps, comp);
        prv->comps_len++;
    }

    if (free_flag) {
        g_byte_array_free(buf, TRUE);
    }
    return prv;
}

// Hàm serialize private key: chuyển đối tượng bswabe_prv_t thành một GByteArray
GByteArray* bswabe_prv_serialize(bswabe_prv_t* prv) {
    // Tạo GByteArray để lưu dữ liệu
    GByteArray* b = g_byte_array_new();

    // 1) Ghi số lượng comps (comps_len)
    uint32_t n = prv->comps_len;
    g_byte_array_append(b, (const guint8*)&n, sizeof(uint32_t));

    // 2) Ghi g2 d
    serialize_g2(b, prv->d);

    // 3) Ghi từng comp
    for (int i = 0; i < n; i++) {
        bswabe_prv_comp_t* comp = &g_array_index(prv->comps, bswabe_prv_comp_t, i);

        // 3.1) Ghi độ dài attr (nếu attr != NULL)
        if (!comp->attr) {
            // Nếu bạn muốn cho phép attr=NULL, thì đặt length=0
            uint32_t attr_len = 0;
            g_byte_array_append(b, (const guint8*)&attr_len, 4);
        } else {
            uint32_t attr_len = strlen(comp->attr);
            g_byte_array_append(b, (const guint8*)&attr_len, 4);
            // 3.2) Ghi nội dung attr
            g_byte_array_append(b, (const guint8*)comp->attr, attr_len);
        }

        // 3.3) Ghi g2 comp->d
        serialize_g2(b, comp->d);

        // 3.4) Ghi g1 comp->dp
        serialize_g1(b, comp->dp);

        // 3.5) Ghi g2 comp->z
        serialize_g2(b, comp->z);

        // 3.6) Ghi g1 comp->zp
        serialize_g1(b, comp->zp);

        // Nếu bạn không dùng z, zp, có thể bỏ
    }

    return b;
}

// Hàm unserialize ciphertext: đọc từ GByteArray và khởi tạo một đối tượng bswabe_cph_t.
bswabe_cph_t* bswabe_cph_unserialize(bswabe_pub_t* pub, GByteArray* buf, int free_flag) {
    int offset = 0;
    bswabe_cph_t* cph = malloc(sizeof(bswabe_cph_t));
    if (!cph) return NULL;
    
    gt_null(cph->cs);
    gt_new(cph->cs);
    g1_null(cph->c);
    g1_new(cph->c);
    
    unserialize_gt(buf, &offset, cph->cs);
    unserialize_g1(buf, &offset, cph->c);
    
    // Unserialize cây policy toàn bộ
    cph->p = unserialize_policy(pub, buf, &offset);
    
    // Nếu cần, có thể khôi phục chuỗi policy gốc (tùy chọn)
    // cph->policy = strdup(...);
    
    if (free_flag) {
        g_byte_array_free(buf, TRUE);
    }
    return cph;
}

// Hàm serialize ciphertext: chuyển đối tượng bswabe_cph_t thành một GByteArray
GByteArray* bswabe_cph_serialize(bswabe_cph_t* cph) {
    GByteArray* buf = g_byte_array_new();
    // Serialize cs và c
    serialize_gt(buf, cph->cs);
    serialize_g1(buf, cph->c);
    // Serialize toàn bộ cây policy
    serialize_policy(buf, cph->p);
    return buf;
}

void bswabe_prv_free(bswabe_prv_t* prv) {
    g2_free(prv->d);
    free(prv);
}

void bswabe_cph_free(bswabe_cph_t* cph) {
    gt_free(cph->cs);
    g1_free(cph->c);
    free(cph);
}

void serialize_policy(GByteArray *b, bswabe_policy_t *p) {
    // Serialize ngưỡng k
    serialize_uint32(b, (uint32_t) p->k);
    
    // Serialize số lượng con
    uint32_t num_children = p->children->len;
    serialize_uint32(b, num_children);
    
    // Nếu là nút lá (leaf) thì num_children == 0
    if(num_children == 0) {
        // Serialize chuỗi attribute (nếu có)
        if(p->attr != NULL) {
            uint32_t attr_len = (uint32_t) strlen(p->attr); 
            serialize_uint32(b, attr_len);
            g_byte_array_append(b, (const guint8*) p->attr, attr_len);
        } else {
            serialize_uint32(b, 0);
        }
        // Serialize p->c (G1)
        serialize_g1(b, p->c);
        // Serialize p->cp (G2)
        serialize_g2(b, p->cp);
        // Serialize đa thức q:
        if(p->q != NULL) {
            serialize_uint32(b, (uint32_t) p->q->deg);
            for (int i = 0; i <= p->q->deg; i++) {
                serialize_bn(b, p->q->coef[i]);
            }
        } else {
            // Nếu không có đa thức, ghi 0 (bậc 0) – tùy chọn, hoặc một giá trị đặc biệt như 0.
            serialize_uint32(b, 0);
        }
    } else {
        // Nếu là nút nội, không có attribute và các phần tử tính toán, chỉ cần đệ quy serialize các con.
        for (int i = 0; i < num_children; i++) {
            bswabe_policy_t *child = g_ptr_array_index(p->children, i);
            serialize_policy(b, child);
        }
    }
}

bswabe_policy_t* unserialize_policy(bswabe_pub_t *pub, GByteArray *b, int *offset) {
    // Cấp phát bộ nhớ cho một nút policy mới
    bswabe_policy_t *p = malloc(sizeof(bswabe_policy_t));
    if (!p) {
        die("Memory allocation failed in unserialize_policy()");
    }
    p->children = g_ptr_array_new();
    p->q = NULL;
    p->attr = NULL; // khởi tạo mặc định
    p->satl = g_array_new(FALSE, FALSE, sizeof(int));
    
    // Đọc ngưỡng k
    p->k = (int) unserialize_uint32(b, offset);
    // Đọc số lượng children
    uint32_t num_children = unserialize_uint32(b, offset);
    
    if(num_children == 0) {
        // Đây là nút lá, nên đọc chuỗi attribute
        uint32_t attr_len = unserialize_uint32(b, offset);
        if(attr_len > 0) {
            p->attr = malloc(attr_len + 1);
            if (!p->attr) die("Memory allocation failed in unserialize_policy (attr)");
            memcpy(p->attr, b->data + *offset, attr_len);
            p->attr[attr_len] = '\0';
            *offset += attr_len;
        }
        // Khởi tạo và unserialize p->c (G1)
        g1_null(p->c);
        g1_new(p->c);
        unserialize_g1(b, offset, p->c);
        // Khởi tạo và unserialize p->cp (G2)
        g2_null(p->cp);
        g2_new(p->cp);
        unserialize_g2(b, offset, p->cp);
        // Đọc đa thức q:
        uint32_t deg = unserialize_uint32(b, offset);
            p->q = malloc(sizeof(bswabe_polynomial_t));
            if(!p->q) die("Memory allocation failed in unserialize_policy (poly)");
            p->q->deg = (int) deg;
            p->q->coef = malloc((p->q->deg + 1) * sizeof(bn_t));
            if(!p->q->coef) die("Memory allocation failed in unserialize_policy (coef)");
            for (int i = 0; i <= p->q->deg; i++) {
                // Cấp phát và đọc từng hệ số bn
                bn_null(p->q->coef[i]);
                bn_new(p->q->coef[i]);
                unserialize_bn(b, offset, p->q->coef[i]);
            }
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

