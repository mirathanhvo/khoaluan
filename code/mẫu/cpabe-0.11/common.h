#ifndef COMMON_H
#define COMMON_H

#include <relic/relic.h>
#include <glib.h>

#ifndef fp12_norm
static inline void fp12_norm(fp12_t m) {
    // Chuyển phần tử FP12 m về dạng chuẩn bằng cách sử dụng fp12_conv_cyc.
    // Hàm này sẽ ghi kết quả vào m.
    fp12_conv_cyc(m, m);
}
#endif
#define AES_KEY_LEN 16
#define IV_SIZE 12      // ví dụ dùng AES-GCM IV 96-bit
#define TAG_SIZE 16     // Tag 128-bit của AES-GCM

#define gt_norm(m) fp12_norm(m)
#define SAFE_GT_CAPACITY 1024 
#define HEADER_SIZE (sizeof(uint32_t) * 2)

#ifndef CPABE_USAGE
#define CPABE_USAGE "Usage: cpabe-setup [OPTION ...]\n" \
"\nGenerate system parameters, a public key, and a master secret key\n" \
"for use with cpabe-keygen, cpabe-enc, and cpabe-dec.\n" \
"\nOutput will be written to the files \"pub_key\" and \"master_key\"\n" \
"unless the --output-public-key or --output-master-key options are used.\n" \
"\nMandatory arguments to long options are mandatory for short options too.\n\n" \
" -h, --help                    print this message\n\n" \
" -v, --version                 print version information\n\n" \
" -p, --output-public-key FILE  write public key to FILE\n\n" \
" -m, --output-master-key FILE  write master secret key to FILE\n\n" \
" -d, --deterministic           use deterministic \"random\" numbers\n"
#endif

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <relic/relic.h>
#include <glib.h>

/*
    This contains data structures and procedures common throughout the tools.
*/

/*
    TODO if SSL SHA1 not available, use built-in one (sha1.c)
*/

// Định nghĩa biến toàn cục
extern char* pub_file;
extern char* in_file;
extern char* out_file;
extern int keep;
extern int deterministic; // Khắc phục lỗi multiple definition
extern char* msk_file;
extern char** attrs;
extern char* prv_file;
extern char last_error[256];

// Khai báo hàm parse_args
void parse_args(int argc, char** argv);

// Đọc nội dung file vào buffer
char* suck_file_str(char* file);
char* suck_stdin();
uint8_t* suck_file(char* file, size_t* len);

// Ghi nội dung buffer vào file
void spit_file(char* file, uint8_t* data, size_t len, int free_mem);

// Đọc & ghi file CP-ABE
void read_cpabe_file(char* file, uint8_t** cph_buf,
                      int* file_len, uint8_t** aes_buf);
void write_cpabe_file(char* file, uint8_t* cph_buf,
                       int file_len, uint8_t* aes_buf);

// Hàm xử lý lỗi
void die(const char* fmt, ...);

// Hàm mã hóa AES-128 sử dụng khóa từ RELIC
uint8_t* aes_128_cbc_encrypt(uint8_t* pt, size_t pt_len, bn_t k, size_t* ct_len);
uint8_t* aes_128_cbc_decrypt(uint8_t* ct, size_t ct_len, bn_t k, size_t* pt_len);

// Prototype cho serialization các đối tượng
void serialize_g1(GByteArray* b, g1_t e);
void unserialize_g1(GByteArray* b, int* offset, g1_t e);

void serialize_g2(GByteArray* b, g2_t e);
void unserialize_g2(GByteArray* b, int* offset, g2_t e);

void serialize_gt(GByteArray* b, gt_t e);
void unserialize_gt(GByteArray* b, int* offset, gt_t e);

void serialize_uint32(GByteArray *b, uint32_t value);
uint32_t unserialize_uint32(GByteArray *b, int *offset);

#define CPABE_VERSION PACKAGE_NAME "%s " PACKAGE_VERSION "\n" \
"\n" \
"Parts Copyright (C) 2006, 2007 John Bethencourt and SRI International.\n" \
"This is free software released under the GPL, see the source for copying\n" \
"conditions. There is NO warranty; not even for MERCHANTABILITY or FITNESS\n" \
"FOR A PARTICULAR PURPOSE.\n" \
"\n" \
"Report bugs to John Bethencourt <bethenco@cs.berkeley.edu>.\n"

// Định nghĩa cấu trúc tham số công khai CP-ABE (dùng elliptic curve của RELIC)
typedef struct {
    g1_t g;  // G1 phần tử của elliptic curve
    g2_t gp; // G2 phần tử của elliptic curve
} public_params;

// Khai báo các hàm
char* bswabe_error();
void raise_error(char* fmt, ...);
void element_from_string(g1_t h, char* s);
void element_from_string_g2(g2_t h, char* s);
void init_aes(bn_t k, int enc, AES_KEY* key, unsigned char* iv);
FILE* fopen_read_or_die(char* file);
FILE* fopen_write_or_die(char* file);

#endif // COMMON_H
