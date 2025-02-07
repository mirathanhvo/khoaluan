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

gint comp_string(gconstpointer a, gconstpointer b) {
    return strcmp(a, b);
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
    bn_rand_mod(alpha, g1_get_ord());
    g2_mul(sk, sk, alpha);
    
    for (int i = 0; i < attr_count; i++) {
        g1_null(d_i[i]);
        g1_new(d_i[i]);
        g1_get_gen(d_i[i]);
        
        // Securely hash the attribute
        uint8_t sha256_digest[32];
        md_map_sh256(sha256_digest, (uint8_t*)attributes[i], strlen(attributes[i]));
        bn_read_bin(h, sha256_digest, sizeof(sha256_digest));
        bn_mod(h, h, g1_get_ord());  // Convert hash to valid integer in group order
        
        // Compute d_i = g1^(1 / (alpha + H(attribute_i)))
        bn_add(denom, h, msk);
        bn_mod_inv(denom, denom, g1_get_ord());  // Modular inverse
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
    FILE* pub_fp = fopen(pub_file, "r");
    if (!pub_fp) {
        printf("Error opening public key file.\n");
        core_clean();
        return 1;
    }
    g1_t pk;
    g1_null(pk);
    g1_new(pk);
    g1_read(pub_fp, pk);
    fclose(pub_fp);

    // Read master secret key
    FILE* msk_fp = fopen(msk_file, "r");
    if (!msk_fp) {
        printf("Error opening master secret key file.\n");
        core_clean();
        return 1;
    }
    bn_t msk;
    bn_null(msk);
    bn_new(msk);
    bn_read(msk_fp, msk);
    fclose(msk_fp);

    // Generate attribute keys
    g2_t sk;
    g1_t* d_i = malloc(attr_count * sizeof(g1_t));
    keygen(sk, d_i, msk, attrs, attr_count);

    // Save secret key and attribute keys
    FILE* out_fp = fopen(out_file, "w");
    if (!out_fp) {
        printf("Error opening private key file.\n");
        core_clean();
        return 1;
    }
    g2_write(out_fp, sk);
    for (int i = 0; i < attr_count; i++) {
        g1_write(out_fp, d_i[i]);
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
