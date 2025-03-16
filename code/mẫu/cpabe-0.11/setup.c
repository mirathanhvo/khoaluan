#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <relic.h>
#include <relic_test.h>
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

    parse_args(argc, argv);

    if (core_init() != RLC_OK) {
        printf("Error initializing RELIC.\n");
        exit(1);
    }
    if (pc_param_set_any() != RLC_OK) {
        printf("Error setting pairing parameters.\n");
        core_clean();
        exit(1);
    }
    printf("Pairing parameters in setup:\n");
    pc_param_print();  // Không truyền đối số

    bn_t order;
    bn_null(order);
    bn_new(order);
    ep_curve_get_ord(order);
    printf("Order in setup: ");
    bn_print(order);
    printf("\n");

    if (deterministic) {
        uint8_t seed[20] = "deterministic_seed";
        rand_seed(seed, 20);
    }
    rand_init();

    // Gọi bswabe_setup
    bswabe_pub_t* pub = NULL;
    bswabe_msk_t* msk = NULL;
    bswabe_setup(&pub, &msk);

    // Debug: kiểm tra nếu msk không tồn tại
    if (!msk) {
        fprintf(stderr, "ERROR: bswabe_setup() failed to generate master key.\n");
        return 1;
    }

    // In ra các phần tử quan trọng của public key
    printf("Public key element g in setup:\n");
    ep_print(pub->g);
    printf("\nPublic key element gp in setup:\n");
    ep2_print(pub->gp);  // Sửa ở đây: dùng ep2_print thay vì ep_print
    printf("\n");

    // Serialize public key
    GByteArray* pub_data = bswabe_pub_serialize(pub);
    FILE* pub_fp = fopen(pub_file, "wb");
    if (!pub_fp) {
        fprintf(stderr, "Error opening pub_file.\n");
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
        bn_free(order);
        core_clean();
        return 1;
    }
    FILE* msk_fp = fopen(msk_file, "wb");
    if (!msk_fp) {
        fprintf(stderr, "Error opening msk_file.\n");
        bswabe_pub_free(pub);
        bswabe_msk_free(msk);
        g_byte_array_free(msk_data, TRUE);
        bn_free(order);
        core_clean();
        return 1;
    }
    fwrite(msk_data->data, 1, msk_data->len, msk_fp);
    fclose(msk_fp);
    g_byte_array_free(msk_data, TRUE);

    // Giải phóng
    bswabe_pub_free(pub);
    bswabe_msk_free(msk);
    bn_free(order);

    core_clean();
    return 0;
}
