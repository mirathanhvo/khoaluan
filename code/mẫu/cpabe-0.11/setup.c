#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <relic.h>
#include <relic_test.h>

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
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help                    print this message\n\n"
" -v, --version                 print version information\n\n"
" -p, --output-public-key FILE  write public key to FILE\n\n"
" -m, --output-master-key FILE  write master secret key to FILE\n\n"
" -d, --deterministic           use deterministic \"random\" numbers\n"
"                               (only for debugging)\n\n"
"";

int main(int argc, char** argv) {
    fprintf(stderr, "Build date: %s, time: %s\n", __DATE__, __TIME__);
    fflush(stderr);

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

    if (pc_param_set_any() != RLC_OK) {
        printf("Error setting pairing parameters.\n");
        core_clean();
        return 1;
    }

    bn_t order;
    bn_null(order);
    bn_new(order);
    g1_get_ord(order);

    bswabe_pub_t pub;
    g1_new(pub.g);
    g2_new(pub.gp);
    gt_new(pub.g_hat_alpha);
    g1_new(pub.h);

    g1_get_gen(pub.g);
    g2_get_gen(pub.gp);

    bn_t m;
    bn_null(m);
    bn_new(m);
    bn_rand_mod(m, order);

    pc_map(pub.g_hat_alpha, pub.g, pub.gp);
    gt_exp(pub.g_hat_alpha, pub.g_hat_alpha, m);

    g1_rand(pub.h);

    FILE* pub_fp = fopen(pub_file, "wb");
    if (!pub_fp) {
        printf("Error opening public key file.\n");
        core_clean();
        return 1;
    }

    GByteArray* pub_data = g_byte_array_new();

    serialize_g1(pub_data, pub.g);
    serialize_g2(pub_data, pub.gp);
    serialize_gt(pub_data, pub.g_hat_alpha);
    serialize_g1(pub_data, pub.h);

    if (fwrite(pub_data->data, 1, pub_data->len, pub_fp) != pub_data->len) {
        fprintf(stderr, "Error writing public key to file.\n");
        exit(1);
    }
    fclose(pub_fp);
    g_byte_array_free(pub_data, TRUE);

    FILE* msk_fp = fopen(msk_file, "wb");
    if (!msk_fp) {
        printf("Error opening master secret key file.\n");
        core_clean();
        return 1;
    }
    int m_len = bn_size_bin(m);
    uint8_t* m_buf = malloc(m_len);
    bn_write_bin(m_buf, m_len, m);
    if (fwrite(m_buf, 1, m_len, msk_fp) != m_len) {
        fprintf(stderr, "Error writing master secret key.\n");
        exit(1);
    }
    fclose(msk_fp);
    free(m_buf);

    bn_free(m);
    bn_free(order);
    g1_free(pub.g);
    g2_free(pub.gp);
    gt_free(pub.g_hat_alpha);
    g1_free(pub.h);

    core_clean();
    return 0;
}