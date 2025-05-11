#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <relic.h>
#include <glib.h>

#include "bswabe.h"
#include "common.h"

static char* usage =
"Usage: cpabe-setup [OPTION ...]\n"
"\n"
"Generate system parameters, a public key, and a master secret key\n"
"for use with cpabe-keygen, cpabe-enc, and cpabe-dec.\n"
"\n"
"Output will be written to the files \"pub_key\" and \"master_key\"\n"
"unless the --output-public-key or --output-master-key options are\n"
"used.\n"
"\n"
" -h, --help                    print this message\n"
" -v, --version                 print version information\n"
" -p, --output-public-key FILE  write public key to FILE\n"
" -m, --output-master-key FILE  write master secret key to FILE\n"
" -d, --deterministic           use deterministic \"random\" numbers\n"
"                               (only for debugging)\n\n"
"";

int main(int argc, char** argv) {
    fprintf(stderr, "Build date: %s, time: %s\n", __DATE__, __TIME__);
    fflush(stderr);
    printf("Vo Phat Thanh \n");
    parse_args(argc, argv);

    // Initialize RELIC
    if (core_init() != RLC_OK) {
        fprintf(stderr, "Error initializing RELIC.\n");
        exit(1);
    }
    if (pc_param_set_any() != RLC_OK) {
        fprintf(stderr, "Error setting pairing parameters.\n");
        core_clean();
        exit(1);
    }
    printf("Pairing parameters in setup:\n");
    pc_param_print();

    // Deterministic seed if enabled
    if (deterministic) {
        uint8_t seed[20] = "deterministic_seed";
        rand_seed(seed, 20);
    }

    // Initialize variables
    bn_t order, alpha, beta;
    g1_t g1;
    g2_t g2;

    bn_null(order); bn_new(order);
    bn_null(alpha); bn_new(alpha);
    bn_null(beta);  bn_new(beta);
    g1_null(g1);    g1_new(g1);
    g2_null(g2);    g2_new(g2);

    // Get group order
    g1_get_ord(order);

    // Generate random alpha and beta
    bn_rand_mod(alpha, order);
    bn_rand_mod(beta, order);

    // Get random generators for G1 and G2
    g1_get_gen(g1);
    g2_get_gen(g2);

    // Call bswabe_setup
    bswabe_pub_t* pub = NULL;
    bswabe_msk_t* msk = NULL;
    bswabe_setup(&pub, &msk, g1, g2, alpha, beta, order);

    // Debug: Check if setup failed
    if (!pub || !msk) {
        fprintf(stderr, "ERROR: bswabe_setup() failed.\n");
        core_clean();
        return 1;
    }

    // Serialize public key
    GByteArray* pub_data = bswabe_pub_serialize(pub);
    FILE* pub_fp = fopen(pub_file, "wb");
    if (!pub_fp) {
        fprintf(stderr, "Error opening pub_file.\n");
        bswabe_pub_free(pub);
        bswabe_msk_free(msk);
        core_clean();
        return 1;
    }
    fwrite(pub_data->data, 1, pub_data->len, pub_fp);
    fclose(pub_fp);
    g_byte_array_free(pub_data, TRUE);

    // Serialize master key
    GByteArray* msk_data = bswabe_msk_serialize(msk);
    if (!msk_data) {
        fprintf(stderr, "ERROR: bswabe_msk_serialize() returned NULL.\n");
        bswabe_pub_free(pub);
        bswabe_msk_free(msk);
        core_clean();
        return 1;
    }
    FILE* msk_fp = fopen(msk_file, "wb");
    if (!msk_fp) {
        fprintf(stderr, "Error opening msk_file.\n");
        bswabe_pub_free(pub);
        bswabe_msk_free(msk);
        g_byte_array_free(msk_data, TRUE);
        core_clean();
        return 1;
    }
    fwrite(msk_data->data, 1, msk_data->len, msk_fp);
    fclose(msk_fp);
    g_byte_array_free(msk_data, TRUE);

    // Cleanup
    bn_free(order);
    bn_free(alpha);
    bn_free(beta);
    g1_free(g1);
    g2_free(g2);
    bswabe_pub_free(pub);
    bswabe_msk_free(msk);
    core_clean();

    return 0;
}
