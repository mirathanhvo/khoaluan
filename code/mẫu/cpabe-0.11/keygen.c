#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <relic.h>
#include <relic_test.h>

#include "bswabe.h"
#include "common.h"

char* usage =
"Usage: cpabe-keygen [OPTION ...] PUB_KEY MASTER_KEY ATTR [ATTR ...]\n"
"\n"
"Generate a key with the listed attributes using public key PUB_KEY and\n"
"master secret key MASTER_KEY. Output will be written to the file\n"
"\"priv_key\" unless the -o option is specified.\n"
"\n"
"Attributes come in two forms: non-numerical and numerical. Non-numerical\n"
"attributes are simply any string of letters, digits, and underscores\n"
"beginning with a letter.\n"
"\n"
"Numerical attributes are specified as `attr = N', where N is a non-negative\n"
"integer less than 2^64 and `attr' is another string. The whitespace around\n"
"the `=' is optional. One may specify an explicit length of k bits for the\n"
"integer by giving `attr = N#k'. Note that any comparisons in a policy given\n"
"to cpabe-enc(1) must then specify the same number of bits, e.g.,\n"
"`attr > 5#12'.\n"
"\n"
"The keywords `and', `or', and `of', are reserved for the policy language\n"
"of cpabe-enc (1) and may not be used for either type of attribute.\n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help               print this message\n\n"
" -v, --version            print version information\n\n"
" -o, --output FILE        write resulting key to FILE\n\n"
" -d, --deterministic      use deterministic \"random\" numbers\n"
"                          (only for debugging)\n\n"
"";

char* pub_file = 0;
char* msk_file = 0;
char** attrs = 0;
char* out_file = "priv_key";

int comp_string(const void* a, const void* b) {
    return strcmp(*(const char**)a, *(const char**)b);
}

void parse_args(int argc, char** argv) {
    int i;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            printf("%s", usage);
            exit(0);
        } else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--version")) {
            printf("cpabe-keygen version 1.0\n");
            exit(0);
        } else if (!strcmp(argv[i], "-o") || !strcmp(argv[i], "--output")) {
            if (i + 1 < argc)
                out_file = argv[++i];
            else {
                fprintf(stderr, "Error: --output requires a file name\n");
                exit(1);
            }
        } else if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--deterministic")) {
            rand_state state;
            rand_init(&state, RLC_RAND);
            rand_seed(&state, (const uint8_t*)"deterministic_seed", 20);
        } else if (!pub_file) {
            pub_file = argv[i];
        } else if (!msk_file) {
            msk_file = argv[i];
        } else {
            attrs = &argv[i];
            break;
        }
    }

    if (!pub_file || !msk_file || !attrs) {
        fprintf(stderr, "Error: missing required arguments\n");
        printf("%s", usage);
        exit(1);
    }
}

void keygen(g2_t sk, g1_t* d_i, bn_t msk, char** attributes, int attr_count) {
    bn_t alpha, h, denom;
    bn_null(alpha);
    bn_null(h);
    bn_null(denom);
    bn_new(alpha);
    bn_new(h);
    bn_new(denom);
    
    g2_null(sk);
    g2_new(sk);
    g2_get_gen(sk);
    
    // Generate random alpha (master secret key)
    bn_rand_mod(alpha, msk);
    g2_mul(sk, sk, alpha);
    
    for (int i = 0; i < attr_count; i++) {
        g1_null(d_i[i]);
        g1_new(d_i[i]);
        g1_get_gen(d_i[i]);
        
        // Securely hash the attribute
        uint8_t sha256_digest[32];
        md_map_sh256(sha256_digest, (uint8_t*)attributes[i], strlen(attributes[i]));
        bn_read_bin(h, sha256_digest, sizeof(sha256_digest));
        bn_mod(h, h, msk);  // Convert hash to valid integer in group order
        
        // Compute d_i = g1^(1 / (alpha + H(attribute_i)))
        bn_add(denom, h, msk);
        bn_mod_inv(denom, denom, msk);  // Modular inverse
        g1_mul(d_i[i], d_i[i], denom);
    }
    
    bn_free(alpha);
    bn_free(h);
    bn_free(denom);
}

int main(int argc, char** argv) {
    parse_args(argc, argv);

    if (core_init() != RLC_OK) {
        core_clean();
        printf("Error initializing RELIC.\n");
        return 1;
    }

    // Read public key
    FILE* pub_fp = fopen(pub_file, "rb");
    if (!pub_fp) {
        printf("Error opening public key file.\n");
        core_clean();
        return 1;
    }
    g1_t pk;
    g1_null(pk);
    g1_new(pk);
    uint8_t pk_buffer[RLC_EP_SIZE];
    fread(pk_buffer, sizeof(uint8_t), RLC_EP_SIZE, pub_fp);
    g1_read_bin(pk, pk_buffer, RLC_EP_SIZE);
    fclose(pub_fp);

    // Read master secret key
    FILE* msk_fp = fopen(msk_file, "rb");
    if (!msk_fp) {
        printf("Error opening master secret key file.\n");
        g1_free(pk);
        core_clean();
        return 1;
    }
    bn_t msk;
    bn_null(msk);
    bn_new(msk);
    uint8_t msk_buffer[RLC_BN_SIZE];
    fread(msk_buffer, sizeof(uint8_t), RLC_BN_SIZE, msk_fp);
    bn_read_bin(msk, msk_buffer, RLC_BN_SIZE);
    fclose(msk_fp);

    // Generate attribute keys
    int attr_count = argc - (attrs - argv);

    g2_t sk;
    g1_t* d_i = malloc(attr_count * sizeof(g1_t));
    for (int i = 0; i < attr_count; i++) {
        g1_null(d_i[i]);
        g1_new(d_i[i]);
    }
    keygen(sk, d_i, msk, attrs, attr_count);

    // Save secret key and attribute keys
    FILE* out_fp = fopen(out_file, "wb");
    if (!out_fp) {
        printf("Error opening private key file.\n");
        for (int i = 0; i < attr_count; i++) {
            g1_free(d_i[i]);
        }
        free(d_i);
        g1_free(pk);
        g2_free(sk);
        bn_free(msk);
        core_clean();
        return 1;
    }
    uint8_t sk_buffer[RLC_EP_SIZE];
    int sk_len = g2_size_bin(sk, 1);
    g2_write_bin(sk_buffer, sk_len, sk, 1);
    fwrite(sk_buffer, sizeof(uint8_t), sk_len, out_fp);
    for (int i = 0; i < attr_count; i++) {
        uint8_t di_buffer[RLC_EP_SIZE];
        int di_len = g1_size_bin(d_i[i], 1);
        g1_write_bin(di_buffer, di_len, d_i[i], 1);
        fwrite(di_buffer, sizeof(uint8_t), di_len, out_fp);
        g1_free(d_i[i]);
    }
    fclose(out_fp);

    // Clean up
    bn_free(msk);
    g1_free(pk);
    g2_free(sk);
    free(d_i);

    core_clean();
    return 0;
}
