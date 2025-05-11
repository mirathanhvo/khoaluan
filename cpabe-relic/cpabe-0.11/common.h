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
extern int deterministic;
extern char* msk_file;
extern char** attrs;
extern char* prv_file;
extern char last_error[256];

// Khai báo hàm parse_args
void parse_args(int argc, char** argv);

// Đọc nội dung file vào buffer
char* suck_file_str(char* file);
char* suck_stdin();
GByteArray* suck_file( char* file );

// Ghi nội dung buffer vào file
void spit_file(char* file, uint8_t* data, size_t len, int free_mem);

// Đọc & ghi file CP-ABE
void read_cpabe_file(char* file, uint8_t** cph_buf, int* cph_len,
                     uint8_t** aes_buf, int* aes_len, uint8_t* iv, uint8_t* tag);
void write_cpabe_file(char* file, uint8_t* cph_buf, int cph_len,
                      uint8_t* aes_buf, int aes_len, uint8_t* iv, uint8_t* tag);

// Hàm xử lý lỗi
void die(const char* fmt, ...);

// Hàm mã hóa AES-128 sử dụng khóa từ RELIC
uint8_t* aes_128_cbc_encrypt(uint8_t* pt, size_t pt_len, bn_t k, size_t* ct_len);
uint8_t* aes_128_cbc_decrypt(uint8_t* ct, size_t ct_len, bn_t k, size_t* pt_len);

#define CPABE_VERSION PACKAGE_NAME " %s " PACKAGE_VERSION "\n" \
"\n" \
"Copyright (C) 2025, improved and adapted to RELIC by Vo Phat ThanhThanh.\n" \
"Original parts (C) 2006, 2007 John Bethencourt and SRI International.\n" \
"\n" \
"This is free software released under the GPL. See the source code for\n" \
"copying conditions. There is NO warranty; not even for MERCHANTABILITY\n" \
"or FITNESS FOR A PARTICULAR PURPOSE.\n" \
"\n" \
"For bug reports, contact: thanh_dth216157@student.agu.edu.vn\n"
