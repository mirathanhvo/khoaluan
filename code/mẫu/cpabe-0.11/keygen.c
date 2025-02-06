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

void parse_args(int argc, char** argv) {
    int i;
    GSList* alist = 0;
    GSList* ap;
    int n;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            printf("%s", usage);
            exit(0);
        } else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--version")) {
            printf("cpabe-keygen version 1.0\n");
            exit(0);
        } else if (!strcmp(argv[i], "-o") || !strcmp(argv[i], "--output")) {
            if (++i >= argc) {
                fprintf(stderr, "Error: --output requires a file name\n");
                exit(1);
            } else {
                out_file = argv[i];
            }
        } else if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--deterministic")) {
            core_set_rand_method(RAND_SEED);
        } else if (!pub_file) {
            pub_file = argv[i];
        } else if (!msk_file) {
            msk_file = argv[i];
        } else {
            alist = g_slist_append(alist, argv[i]);
        }
    }

    if (!pub_file || !msk_file || !alist) {
        fprintf(stderr, "%s", usage);
        exit(1);
    }

    alist = g_slist_sort(alist, comp_string);
    n = g_slist_length(alist);

    attrs = malloc((n + 1) * sizeof(char*));
    i = 0;
    for (ap = alist; ap; ap = ap->next) {
        attrs[i++] = ap->data;
    }
    attrs[i] = 0;
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

    // Generate private key
    bn_t r;
    g1_t d;
    bn_null(r);
    g1_null(d);
    bn_new(r);
    g1_new(d);

    bn_rand_mod(r, g1_get_ord());
    g1_mul(d, pk, r);

    // Save private key
    FILE* out_fp = fopen(out_file, "w");
    if (!out_fp) {
        printf("Error opening private key file.\n");
        core_clean();
        return 1;
    }
    g1_write(out_fp, d);
    fclose(out_fp);

    // Clean up
    bn_free(msk);
    g1_free(pk);
    bn_free(r);
    g1_free(d);

    core_clean();
    return 0;
}
