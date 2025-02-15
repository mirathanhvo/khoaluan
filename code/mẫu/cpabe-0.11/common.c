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
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <relic/relic.h>

#include "common.h"

void init_aes(bn_t k, int enc, AES_KEY* key, unsigned char* iv) {
    int key_len;
    unsigned char key_buf[32]; // 256 bits max for AES

    key_len = bn_size_bin(k);
    if (key_len > 32) {
        key_len = 32;
    }
    bn_write_bin(key_buf, key_len, k);

    if (enc) {
        AES_set_encrypt_key(key_buf, 128, key);
    } else {
        AES_set_decrypt_key(key_buf, 128, key);
    }

    memset(iv, 0, 16);
}

uint8_t* aes_128_cbc_encrypt(uint8_t* pt, size_t pt_len, bn_t k, size_t* ct_len) {
    AES_KEY enc_key;
    unsigned char iv[16];
    init_aes(k, 1, &enc_key, iv);

    *ct_len = ((pt_len + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    uint8_t* ct = (uint8_t*)malloc(*ct_len);

    AES_cbc_encrypt(pt, ct, pt_len, &enc_key, iv, AES_ENCRYPT);
    return ct;
}

uint8_t* aes_128_cbc_decrypt(uint8_t* ct, size_t ct_len, bn_t k, size_t* pt_len) {
    AES_KEY dec_key;
    unsigned char iv[16];
    init_aes(k, 0, &dec_key, iv);

    uint8_t* pt = (uint8_t*)malloc(ct_len);
    AES_cbc_encrypt(ct, pt, ct_len, &dec_key, iv, AES_DECRYPT);
    *pt_len = ct_len; // Assuming no padding for simplicity
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

uint8_t* suck_file(char* file, size_t* len) {
    FILE* f = fopen(file, "rb");
    if (!f) {
        die("can't read file: %s\n", file);
    }
    fseek(f, 0, SEEK_END);
    *len = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t* data = (uint8_t*)malloc(*len);
    if (fread(data, 1, *len, f) != *len) {
        die("error reading file: %s\n", file);
    }
    fclose(f);
    return data;
}

char* suck_file_str(char* file) {
    size_t len;
    uint8_t* data = suck_file(file, &len);
    char* str = (char*)malloc(len + 1);
    memcpy(str, data, len);
    str[len] = '\0';
    free(data);
    return str;
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

void read_cpabe_file(char* file, uint8_t** cph_buf, int* file_len, uint8_t** aes_buf) {
    FILE* f = fopen(file, "rb");
    if (!f) {
        die("can't read file: %s\n", file);
    }

    if (fread(file_len, sizeof(int), 1, f) != 1) {
        die("error reading file length: %s\n", file);
    }
    int aes_len;
    if (fread(&aes_len, sizeof(int), 1, f) != 1) {
        die("error reading AES length: %s\n", file);
    }
    *aes_buf = (uint8_t*)malloc(aes_len);
    if (fread(*aes_buf, 1, aes_len, f) != aes_len) {
        die("error reading AES buffer: %s\n", file);
    }

    int cph_len;
    if (fread(&cph_len, sizeof(int), 1, f) != 1) {
        die("error reading ciphertext length: %s\n", file);
    }
    *cph_buf = (uint8_t*)malloc(cph_len);
    if (fread(*cph_buf, 1, cph_len, f) != cph_len) {
        die("error reading ciphertext buffer: %s\n", file);
    }

    fclose(f);
}

void write_cpabe_file(char* file, uint8_t* cph_buf, int file_len, uint8_t* aes_buf) {
    FILE* f = fopen(file, "wb");
    if (!f) {
        die("can't write file: %s\n", file);
    }

    if (fwrite(&file_len, sizeof(int), 1, f) != 1) {
        die("error writing file length: %s\n", file);
    }
    int aes_len = file_len; // Use file_len instead of strlen
    if (fwrite(&aes_len, sizeof(int), 1, f) != 1) {
        die("error writing AES length: %s\n", file);
    }
    if (fwrite(aes_buf, 1, aes_len, f) != aes_len) {
        die("error writing AES buffer: %s\n", file);
    }

    int cph_len = file_len; // Use file_len instead of strlen
    if (fwrite(&cph_len, sizeof(int), 1, f) != 1) {
        die("error writing ciphertext length: %s\n", file);
    }
    if (fwrite(cph_buf, 1, cph_len, f) != cph_len) {
        die("error writing ciphertext buffer: %s\n", file);
    }

    fclose(f);
}

void die(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    exit(1);
}
