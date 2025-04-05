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

    printf("Step 1: rand_init\n");
    fflush(stdout);
    rand_init();

    printf("Step 2: g2_new\n");
    fflush(stdout);
    g2_t g2;
    g2_null(g2);    // BẮT BUỘC: Initialize g2 to avoid undefined behavior
    g2_new(g2);     // Allocate memory for g2

    printf("Step 3: g2_rand\n");
    fflush(stdout);
    g2_rand(g2);    // Generate a random element in G2

   // Manually set g2 as the generator for G2
    ep2_t g2_gen;
    ep2_null(g2_gen);
    ep2_new(g2_gen);
    ep2_copy(g2_gen, g2);  // Copy the generated g2 to g2_gen
    printf("Step 4: Done rand g2\n");
    fflush(stdout);

    // Generate a random beta
    bn_t beta;
    bn_new(beta);
    bn_rand_mod(beta, order);  // Generate beta randomly within the group order

    // Compute inv_beta = 1 / beta mod order
    bn_t inv_beta;
    bn_null(inv_beta);
    bn_new(inv_beta);

    // Use bn_mod_inv for modular inversion
    bn_mod_inv(inv_beta, beta, order);  // Compute inv_beta = beta^(-1) mod order

    // Compute g2^(1/beta) in G2
    ep2_t g2_exp_result;
    ep2_new(g2_exp_result);
    ep2_mul(g2_exp_result, g2, inv_beta);  // Corrected: Use ep2_mul for scalar multiplication in G2

    // Debug: Print the computed values
    printf("g2^(1/beta) in G2 = ");
    ep2_print(g2_exp_result);  // Corrected: Use ep2_print for G2
    printf("\n");

    // Convert g2_exp_result (G2) to bytes
    uint8_t buf[128];
    int len = ep2_size_bin(g2_exp_result, 1);  // 1: compressed
    ep2_write_bin(buf, len, g2_exp_result, 1);

    // Map to G1
    ep_t g1;
    ep_new(g1);
    ep_map(g1, buf, len);  // Hash the byte array into G1

    // Debug: Print the computed g1
    printf("g1 = ");
    ep_print(g1);
    printf("\n");

    // Perform pairing
    gt_t pairing_result;
    gt_new(pairing_result);
    pc_map(pairing_result, g1, g2_exp_result);  // Pairing e(g1, g2_exp_result)

    // Debug: Print the pairing result
    printf("e(g1, g2) = ");
    gt_print(pairing_result);
    printf("\n");

    // Free temporary variables
    bn_free(inv_beta);
    ep2_free(g2_exp_result);
    ep_free(g1);
    gt_free(pairing_result);

    // Initialize alpha
    bn_t alpha;
    bn_null(alpha);
    bn_new(alpha);
    bn_rand_mod(alpha, order);  // Generate a random alpha

    // Gọi bswabe_setup
    bswabe_pub_t* pub = NULL;
    bswabe_msk_t* msk = NULL;
    bswabe_setup(&pub, &msk, g1, g2, alpha, beta, order);

    // Free alpha after use
    bn_free(alpha);

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