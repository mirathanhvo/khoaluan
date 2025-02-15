#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <relic/relic.h>

/*
	Include glib.h and pbc.h before including this file.

	This contains data structures and procedures common throughout the
	tools.
*/

/*
	TODO if ssl sha1 not available, use built in one (sha1.c)
*/

char* suck_file_str(char* file);
char* suck_stdin();
uint8_t* suck_file(char* file, size_t* len);

void spit_file(char* file, uint8_t* data, size_t len, int free_mem);

void read_cpabe_file(char* file, uint8_t** cph_buf,
                      int* file_len, uint8_t** aes_buf);

void write_cpabe_file(char* file, uint8_t* cph_buf,
                       int file_len, uint8_t* aes_buf);

void die(const char* fmt, ...);

uint8_t* aes_128_cbc_encrypt(uint8_t* pt, size_t pt_len, bn_t k, size_t* ct_len);
uint8_t* aes_128_cbc_decrypt(uint8_t* ct, size_t ct_len, bn_t k, size_t* pt_len);


#define CPABE_VERSION PACKAGE_NAME "%s " PACKAGE_VERSION "\n" \
"\n" \
"Parts Copyright (C) 2006, 2007 John Bethencourt and SRI International.\n" \
"This is free software released under the GPL, see the source for copying\n" \
"conditions. There is NO warranty; not even for MERCHANTABILITY or FITNESS\n" \
"FOR A PARTICULAR PURPOSE.\n" \
"\n" \
"Report bugs to John Bethencourt <bethenco@cs.berkeley.edu>.\n"

#endif // COMMON_H
