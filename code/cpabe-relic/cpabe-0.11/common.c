#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#define OPENSSL_API_COMPAT 0x10100000L
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <relic/relic.h>
#include <glib.h>
#include <arpa/inet.h>
#include "common.h"

// Định nghĩa biến toàn cục
char* pub_file = NULL;
char* in_file = NULL;
char* out_file = NULL;
int keep = 0;
int deterministic = 0; // Định nghĩa biến toàn cục một lần duy nhất
char* msk_file = NULL;
char** attrs = NULL;
char* prv_file = NULL;
char* policy = NULL; // Thêm biến toàn cục cho POLICY
char last_error[256];

char* bswabe_error() {
    return last_error;
}

void init_aes(bn_t k, int enc, AES_KEY* key, unsigned char* iv) {
    unsigned char key_buf[32]; // 32 bytes = 256 bits

    // Khởi tạo key_buf bằng 0 để tránh rác bộ nhớ nếu bn_write_bin < 32 bytes
    memset(key_buf, 0, 32);

    // Ghi giá trị k vào key_buf (có thể nhỏ hơn 32 byte)
    bn_write_bin(key_buf + (32 - bn_size_bin(k)), bn_size_bin(k), k);

    // Thiết lập khóa AES-256
    if (enc) {
        AES_set_encrypt_key(key_buf, 256, key);
    } else {
        AES_set_decrypt_key(key_buf, 256, key);
    }

    // IV nên là ngẫu nhiên trong thực tế, nhưng ở đây bạn dùng IV = 0 (ok nếu đồng bộ mã/giải mã)
    memset(iv, 0, 16);
}


uint8_t* aes_256_cbc_encrypt(uint8_t* pt, size_t pt_len, bn_t k, size_t* ct_len) {
    AES_KEY enc_key;
    unsigned char iv[16];
    init_aes(k, 1, &enc_key, iv);

    // Ghi độ dài thật (4 byte big endian)
    size_t padded_len = pt_len + 4;
    size_t padding = 16 - (padded_len % 16);
    *ct_len = padded_len + padding;

    uint8_t* padded = calloc(*ct_len, 1);
    padded[0] = (pt_len >> 24) & 0xFF;
    padded[1] = (pt_len >> 16) & 0xFF;
    padded[2] = (pt_len >> 8) & 0xFF;
    padded[3] = (pt_len >> 0) & 0xFF;
    memcpy(padded + 4, pt, pt_len);

    uint8_t* ct = malloc(*ct_len);
    AES_cbc_encrypt(padded, ct, *ct_len, &enc_key, iv, AES_ENCRYPT);
    free(padded);
    return ct;
}


uint8_t* aes_256_cbc_decrypt(uint8_t* ct, size_t ct_len, bn_t k, size_t* pt_len) {
    AES_KEY dec_key;
    unsigned char iv[16];
    init_aes(k, 0, &dec_key, iv);

    uint8_t* padded = malloc(ct_len);
    AES_cbc_encrypt(ct, padded, ct_len, &dec_key, iv, AES_DECRYPT);

    // Đọc độ dài thật từ 4 byte đầu
    *pt_len = (padded[0] << 24) | (padded[1] << 16) | (padded[2] << 8) | padded[3];
    uint8_t* pt = malloc(*pt_len);
    memcpy(pt, padded + 4, *pt_len);
    free(padded);
    return pt;
}


FILE* fopen_read_or_die(char* file) {
    FILE* f = fopen(file, "r");
    if (!f) {
        die("can't read file: %s\n", file);
    }
    return f;
}

FILE* fopen_write_or_die(char* file) {
    FILE* f = fopen(file, "w");
    if (!f) {
        die("can't write file: %s\n", file);
    }
    return f;
}

GByteArray* suck_file(char* file) {
    FILE* f = fopen(file, "rb");
    if (!f)
        die("Cannot open file %s for reading", file);

    fseek(f, 0, SEEK_END);
    int len = ftell(f);
    fseek(f, 0, SEEK_SET);

    GByteArray* b = g_byte_array_sized_new(len);
    fread(b->data, 1, len, f);
    b->len = len;
    fclose(f);

    return b;
}

char*
suck_file_str( char* file )
{
	GByteArray* a;
	char* s;
	unsigned char zero;

	a = suck_file(file);
	zero = 0;
	g_byte_array_append(a, &zero, 1);
	s = (char*) a->data;
	g_byte_array_free(a, 0);

	return s;
}

char* suck_stdin() {
    size_t size = 1024;
    char* buffer = (char*)malloc(size);
    size_t len = 0;
    int c;

    while ((c = fgetc(stdin)) != EOF) {
        if (len + 1 >= size) {
            size *= 2;
            buffer = (char*)realloc(buffer, size);
        }
        buffer[len++] = (char)c;
    }
    buffer[len] = '\0';
    return buffer;
}

void spit_file(char* file, uint8_t* data, size_t len, int free_mem) {
    FILE* f = fopen(file, "wb");
    if (!f) {
        die("can't write file: %s\n", file);
    }
    if (fwrite(data, 1, len, f) != len) {
        die("error writing file: %s\n", file);
    }
    fclose(f);
    if (free_mem) {
        free(data);
    }
}

void read_cpabe_file(char* file, uint8_t** cph_buf, int* cph_len, uint8_t** aes_buf, int* aes_len, uint8_t* iv, uint8_t* tag) {
    FILE* f = fopen(file, "rb");
    if (!f) {
        die("can't read file: %s\n", file);
    }

    uint32_t sym_len_net, abe_len_net;

    fread(iv, 1, 12, f);          // Read IV (12 bytes)
    fread(tag, 1, 16, f);         // Read TAG (16 bytes)
    fread(&sym_len_net, sizeof(uint32_t), 1, f);  // Read AES ciphertext length
    fread(&abe_len_net, sizeof(uint32_t), 1, f);  // Read CP-ABE ciphertext length

    *aes_len = ntohl(sym_len_net);
    *cph_len = ntohl(abe_len_net);

    *aes_buf = malloc(*aes_len);
    *cph_buf = malloc(*cph_len);

    if (!*aes_buf || !*cph_buf) {
        die("Memory allocation failed while reading file: %s\n", file);
    }

    fread(*aes_buf, 1, *aes_len, f);   // Read AES ciphertext
    fread(*cph_buf, 1, *cph_len, f);   // Read CP-ABE ciphertext

    fclose(f);
}

void write_cpabe_file(char* file, uint8_t* cph_buf, int cph_len, uint8_t* aes_buf, int aes_len, uint8_t* iv, uint8_t* tag) {
    FILE* f = fopen(file, "wb");
    if (!f) {
        die("can't write file: %s\n", file);
    }

    uint32_t sym_len = htonl(aes_len);
    uint32_t abe_len = htonl(cph_len);

    fwrite(iv, 1, 12, f);         // Write IV (12 bytes)
    fwrite(tag, 1, 16, f);        // Write TAG (16 bytes)
    fwrite(&sym_len, sizeof(uint32_t), 1, f);  // Write AES ciphertext length
    fwrite(&abe_len, sizeof(uint32_t), 1, f);  // Write CP-ABE ciphertext length
    fwrite(aes_buf, 1, aes_len, f);            // Write AES ciphertext
    fwrite(cph_buf, 1, cph_len, f);            // Write CP-ABE ciphertext

    fclose(f);
}

void die(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    exit(1);
}
