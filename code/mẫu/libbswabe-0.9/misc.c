#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <relic.h>

#include "bswabe.h"
#include "private.h"
#include "../cpabe-0.11/common.h"

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
    uint32_t len = bn_size_bin(n);
    serialize_uint32(b, len);
    unsigned char* buf = malloc(len);
    bn_write_bin(buf, len, n);
    g_byte_array_append(b, buf, len);
    free(buf);
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
    g1_write_bin(buf, len, e, 1);
    g_byte_array_append(b, buf, len);
    free(buf);
}

void unserialize_g1(GByteArray* b, int* offset, g1_t e) {
    uint32_t len = unserialize_uint32(b, offset);
    unsigned char* buf = malloc(len);
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
    g2_write_bin(buf, len, e, 1);
    g_byte_array_append(b, buf, len);
    free(buf);
}

void unserialize_g2(GByteArray* b, int* offset, g2_t e) {
    uint32_t len = unserialize_uint32(b, offset);
    unsigned char* buf = malloc(len);
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
    gt_write_bin(buf, len, e, 1);
    g_byte_array_append(b, buf, len);
    free(buf);
}

void unserialize_gt(GByteArray* b, int* offset, gt_t e) {
    uint32_t len = unserialize_uint32(b, offset);
    unsigned char* buf = malloc(len);
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
    return buf;
}

GByteArray* bswabe_msk_serialize(bswabe_msk_t* msk) {
    GByteArray* b = g_byte_array_new();
    serialize_bn(b, msk->beta);
    serialize_g2(b, msk->g_alpha);
    return b;
}

bswabe_msk_t* bswabe_msk_unserialize(bswabe_pub_t* pub, GByteArray* b, int free) {
    bswabe_msk_t* msk = malloc(sizeof(bswabe_msk_t));
    int offset = 0;
    bn_new(msk->beta);
    g2_new(msk->g_alpha);
    unserialize_bn(b, &offset, msk->beta);
    unserialize_g2(b, &offset, msk->g_alpha);
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

        // comp.z (g1)
        g1_null(comp.z);
        g1_new(comp.z);
        unserialize_g1(buf, &offset, comp.z);

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

        // 3.5) Ghi g1 comp->z
        serialize_g1(b, comp->z);

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
    if (!cph) {
        return NULL;
    }

    // Khởi tạo các thành phần của ciphertext
    gt_null(cph->cs);
    gt_new(cph->cs);

    g1_null(cph->c);
    g1_new(cph->c);

    // Giả sử thứ tự serialize là: cs, c.
    unserialize_gt(buf, &offset, cph->cs);
    unserialize_g1(buf, &offset, cph->c);

    if (free_flag) {
        g_byte_array_free(buf, TRUE);
    }
    return cph;
}

// Hàm serialize ciphertext: chuyển đối tượng bswabe_cph_t thành một GByteArray
GByteArray* bswabe_cph_serialize(bswabe_cph_t* cph) {
    GByteArray* buf = g_byte_array_new();
    // Serialize theo thứ tự: cs, c.
    serialize_gt(buf, cph->cs);
    serialize_g1(buf, cph->c);
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
