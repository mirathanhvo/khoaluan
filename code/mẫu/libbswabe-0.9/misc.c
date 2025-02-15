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

GByteArray* bswabe_pub_serialize(bswabe_pub_t* pub) {
    GByteArray* b = g_byte_array_new();

    serialize_g1(b, pub->g);
    serialize_g1(b, pub->h);
    serialize_g2(b, pub->gp);
    serialize_gt(b, pub->g_hat_alpha);

    return b;
}

bswabe_pub_t* bswabe_pub_unserialize(GByteArray* b, int free) {
    bswabe_pub_t* pub = malloc(sizeof(bswabe_pub_t));
    int offset = 0;

    g1_new(pub->g);
    g1_new(pub->h);
    g2_new(pub->gp);
    gt_new(pub->g_hat_alpha);

    unserialize_g1(b, &offset, pub->g);
    unserialize_g1(b, &offset, pub->h);
    unserialize_g2(b, &offset, pub->gp);
    unserialize_gt(b, &offset, pub->g_hat_alpha);

    if (free) g_byte_array_free(b, 1);
    return pub;
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
