#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <relic.h>
#include <relic_test.h>

#include "bswabe.h"
#include "common.h"

char* usage =
"Usage: cpabe-setup [OPTION ...]\n"
"\n"
"Generate system parameters, a public key, and a master secret key\n"
"for use with cpabe-keygen, cpabe-enc, and cpabe-dec.\n"
"\n"
"Output will be written to the files \"pub_key\" and \"master_key\"\n"
"unless the --output-public-key or --output-master-key options are\n"
"used.\n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help                    print this message\n\n"
" -v, --version                 print version information\n\n"
" -p, --output-public-key FILE  write public key to FILE\n\n"
" -m, --output-master-key FILE  write master secret key to FILE\n\n"
" -d, --deterministic           use deterministic \"random\" numbers\n"
"                               (only for debugging)\n\n"
"";

char* pub_file = "pub_key";
char* msk_file = "master_key";
int deterministic = 0;

void parse_args(int argc, char** argv) {
    int i;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            printf("%s", usage);
            exit(0);
        } else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--version")) {
            printf("cpabe-setup version 1.0\n");
            exit(0);
        } else if (!strcmp(argv[i], "-p") || !strcmp(argv[i], "--output-public-key")) {
            if (i + 1 < argc)
                pub_file = argv[++i];
            else {
                fprintf(stderr, "Error: --output-public-key requires a file name\n");
                exit(1);
            }
        } else if (!strcmp(argv[i], "-m") || !strcmp(argv[i], "--output-master-key")) {
            if (i + 1 < argc)
                msk_file = argv[++i];
            else {
                fprintf(stderr, "Error: --output-master-key requires a file name\n");
                exit(1);
            }
        } else if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--deterministic")) {
            deterministic = 1;
        } else {
            fprintf(stderr, "Error: unknown option %s\n", argv[i]);
            exit(1);
        }
    }
}

int main(int argc, char** argv) {
    parse_args(argc, argv);

    if (core_init() != RLC_OK) {
        core_clean();
        printf("Error initializing RELIC.\n");
        return 1;
    }

    if (deterministic) {
        uint8_t seed[20] = "deterministic_seed";
        rand_seed(seed, 20);
    }

    rand_init();

    if (ep_param_set_any_pairf() != RLC_OK) {
        printf("Error setting pairing parameters.\n");
        core_clean();
        return 1;
    }

    bn_t msk, order;
    ep_t g1, pk;
    ep2_t g2;

    bn_null(msk);
    bn_null(order);
    ep_null(g1);
    ep_null(pk);
    ep2_null(g2);

    bn_new(msk);
    bn_new(order);
    ep_new(g1);
    ep_new(pk);
    ep2_new(g2);

    ep_curve_get_gen(g1);
    ep2_curve_get_gen(g2);
    ep_curve_get_ord(order);

    if (deterministic) {
        bn_set_dig(msk, 12345);  // Use fixed number for debugging
    } else {
        bn_rand_mod(msk, order);  // Generate secure random key
    }

    ep_mul_gen(pk, msk);

    FILE* pub_fp = fopen(pub_file, "wb");
    if (!pub_fp) {
        printf("Error opening public key file.\n");
        core_clean();
        return 1;
    }
    uint8_t buffer[RLC_BN_SIZE];
    int len = ep_size_bin(pk, 1);
    fwrite(&len, sizeof(int), 1, pub_fp);  // Save length first
    ep_write_bin(buffer, len, pk, 1);
    fwrite(buffer, sizeof(uint8_t), len, pub_fp);
    fclose(pub_fp);

    FILE* msk_fp = fopen(msk_file, "wb");
    if (!msk_fp) {
        printf("Error opening master secret key file.\n");
        core_clean();
        return 1;
    }
    uint8_t bn_buffer[RLC_BN_SIZE];
    int bn_len = bn_size_bin(msk);
    fwrite(&bn_len, sizeof(int), 1, msk_fp);  // Save length first
    bn_write_bin(bn_buffer, bn_len, msk);
    fwrite(bn_buffer, sizeof(uint8_t), bn_len, msk_fp);
    fclose(msk_fp);

    bn_free(msk);
    bn_free(order);
    ep_free(g1);
    ep_free(pk);
    ep2_free(g2);

    core_clean();
    return 0;
}