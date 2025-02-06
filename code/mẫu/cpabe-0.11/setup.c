#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
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
            core_set_rand_method(RAND_SEED);
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

    // Initialize pairing parameters for BLS12-381 curve
    if (ep_param_set_any_pairf() != RLC_OK) {
        printf("Error setting pairing parameters.\n");
        core_clean();
        return 1;
    }

    // Generate master secret key and public key
    bn_t msk;
    g1_t g1, pk;
    g2_t g2;

    bn_null(msk);
    g1_null(g1);
    g1_null(pk);
    g2_null(g2);

    bn_new(msk);
    g1_new(g1);
    g1_new(pk);
    g2_new(g2);

    g1_get_gen(g1);
    g2_get_gen(g2);
    bn_rand_mod(msk, g1_get_ord());
    g1_mul_gen(pk, msk);

    // Save public key
    FILE* pub_fp = fopen(pub_file, "w");
    if (!pub_fp) {
        printf("Error opening public key file.\n");
        core_clean();
        return 1;
    }
    g1_write(pub_fp, pk);
    fclose(pub_fp);

    // Save master secret key
    FILE* msk_fp = fopen(msk_file, "w");
    if (!msk_fp) {
        printf("Error opening master secret key file.\n");
        core_clean();
        return 1;
    }
    bn_write(msk_fp, msk);
    fclose(msk_fp);

    // Clean up
    bn_free(msk);
    g1_free(g1);
    g1_free(pk);
    g2_free(g2);

    core_clean();
    return 0;
}
