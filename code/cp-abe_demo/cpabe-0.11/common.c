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

void raise_error(char* fmt, ...) {
#ifdef BSWABE_DEBUG
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    exit(1);
#else
    va_list args;
    va_start(args, fmt);
    vsnprintf(last_error, 256, fmt, args);
    va_end(args);
#endif
}

/*
 * Hàm parse_args mở rộng cho các công cụ cp-abe:
 *
 * - cpabe-setup: Không có đối số vị trí; sử dụng các tùy chọn -p và -m (hoặc mặc định "pub_key", "master_key").
 * - cpabe-keygen: Yêu cầu ít nhất 3 đối số vị trí: PUB_KEY, MASTER_KEY, ATTR [ATTR ...].
 * - cpabe-enc: Yêu cầu ít nhất 2 đối số vị trí: PUB_KEY, FILE; tùy chọn thứ ba là POLICY.
 * - cpabe-dec: Yêu cầu đúng 3 đối số vị trí: PUB_KEY, PRIV_KEY, FILE.
 *
 * Các tùy chọn được hỗ trợ:
 *   -o <file>      : Chỉ định file đầu ra (out_file)
 *   -k             : Gán keep = 1
 *   -d             : Gán deterministic = 1
 *   -h, --help     : In usage và thoát
 *   -v, --version  : (Nếu cần) in thông tin version và thoát
 */
void parse_args(int argc, char** argv) {
    int i;
    int pos_start = -1;
    int is_setup = (strstr(argv[0], "cpabe-setup") != NULL);
    int is_keygen = (strstr(argv[0], "cpabe-keygen") != NULL);
    int is_enc = (strstr(argv[0], "cpabe-enc") != NULL);
    int is_dec = (strstr(argv[0], "cpabe-dec") != NULL);

    // Xử lý các tùy chọn bắt đầu bằng '-'
    for (i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            if (!strcmp(argv[i], "-o")) {
                if (i + 1 < argc) {
                    out_file = argv[++i];
                } else {
                    fprintf(stderr, "Error: Missing output file argument.\n");
                    exit(1);
                }
            } else if (!strcmp(argv[i], "-k")) {
                keep = 1;
            } else if (!strcmp(argv[i], "-d")) {
                deterministic = 1;
            } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
                fprintf(stderr, "%s", CPABE_USAGE);
                exit(0);
            } else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--version")) {
                // In version nếu cần; ví dụ:
                fprintf(stderr, "cpabe version 0.11 (customized)\n");
                exit(0);
            } else {
                fprintf(stderr, "Error: Unknown option %s\n", argv[i]);
                exit(1);
            }
        } else {
            // Lần đầu tiên gặp đối số không bắt đầu bằng '-' => bắt đầu các đối số vị trí
            pos_start = i;
            break;
        }
    }
    int pos_count = (pos_start == -1) ? 0 : (argc - pos_start);

    if (is_setup) {
        // cpabe-setup: không nhận đối số vị trí
        if (pos_count != 0) {
            fprintf(stderr, "Error: cpabe-setup does not accept positional arguments.\n");
            exit(1);
        }
        if (!pub_file) pub_file = "pub_key";
        if (!msk_file) msk_file = "master_key";
    } else if (is_keygen) {
        // cpabe-keygen: yêu cầu ít nhất 3 đối số vị trí: PUB_KEY, MASTER_KEY, ATTR [ATTR ...]
        if (pos_count < 3) {
            fprintf(stderr, "Error: Missing required arguments for cpabe-keygen.\n");
            exit(1);
        }
        pub_file = argv[pos_start];
        msk_file = argv[pos_start + 1];
        int num_attrs = pos_count - 2;
        attrs = malloc((num_attrs + 1) * sizeof(char*));
        for (i = 0; i < num_attrs; i++) {
            attrs[i] = argv[pos_start + 2 + i];
        }
        attrs[num_attrs] = NULL;
    } else if (is_enc) {
        // cpabe-enc: yêu cầu ít nhất 2 đối số vị trí: PUB_KEY, FILE; tùy chọn thứ 3 là POLICY.
        if (pos_count < 2) {
            fprintf(stderr, "Error: Missing required arguments for cpabe-enc.\n");
            exit(1);
        }
        pub_file = argv[pos_start];
        in_file = argv[pos_start + 1];
        if (pos_count >= 3) {
            // Gán đối số thứ 3 làm POLICY
            policy = argv[pos_start + 2];
        }
    } else if (is_dec) {
        // cpabe-dec: yêu cầu đúng 3 đối số vị trí: PUB_KEY, PRIV_KEY, FILE.
        if (pos_count != 3) {
            fprintf(stderr, "Error: cpabe-dec requires exactly 3 positional arguments.\n");
            exit(1);
        }
        pub_file = argv[pos_start];
        prv_file = argv[pos_start + 1];
        in_file = argv[pos_start + 2];
    } else {
        fprintf(stderr, "Error: Unknown command.\n");
        exit(1);
    }
}

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

