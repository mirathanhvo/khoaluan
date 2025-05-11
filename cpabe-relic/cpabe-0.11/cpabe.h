/*
    Include glib.h and relic.h before including this file.

    This contains data structures and procedures common throughout the
    tools.
*/

/*
    TODO if ssl sha1 not available, use built-in one (sha1.c)
*/

#define NUM_ATTR_BITS 32

// Các hàm sẽ sử dụng RELIC thay vì PBC

GByteArray* suck_file( char* file );
void        spit_file( char* file, GByteArray* b );
FILE* fopen_read_or_die( char* file );
FILE* fopen_write_or_die( char* file );
char* suck_file_str( char* file );
char* suck_stdin();
void die(char* fmt, ...);

// Các hàm AES vẫn sử dụng GLib cho mã hóa AES, nhưng RELIC thay thế PBC
GByteArray* aes_128_cbc_encrypt( GByteArray* pt, g1_t k );  // Thay đổi kiểu dữ liệu từ element_t sang g1_t
GByteArray* aes_128_cbc_decrypt( GByteArray* ct, g1_t k );  // Thay đổi kiểu dữ liệu từ element_t sang g1_t


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
