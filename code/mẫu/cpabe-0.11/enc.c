#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <relic.h>
#include <relic_test.h>

#include "bswabe.h"
#include "common.h"
#include "policy_lang.h"

char* usage =
"Usage: cpabe-enc [OPTION ...] PUB_KEY FILE [POLICY]\n"
"\n"
"Encrypt FILE under the decryption policy POLICY using public key\n"
"PUB_KEY. The encrypted file will be written to FILE.cpabe unless\n"
"the -o option is used. The original file will be removed. If POLICY\n"
"is not specified, the policy will be read from stdin.\n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help               print this message\n\n"
" -v, --version            print version information\n\n"
" -k, --keep-input-file    don't delete original file\n\n"
" -o, --output FILE        write resulting key to FILE\n\n"
" -d, --deterministic      use deterministic \"random\" numbers\n"
"                          (only for debugging)\n\n"
"";

char* pub_file = 0;
char* in_file  = 0;
char* out_file = 0;
int   keep     = 0;

char* policy = 0;

void parse_args(int argc, char** argv) {
    int i;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            printf("%s", usage);
            exit(0);
        } else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--version")) {
            printf("cpabe-enc version 1.0\n");
            exit(0);
        } else if (!strcmp(argv[i], "-k") || !strcmp(argv[i], "--keep-input-file")) {
            keep = 1;
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
        } else if (!in_file) {
            in_file = argv[i];
        } else if (!policy) {
            policy = parse_policy_lang(argv[i]);
        } else {
            fprintf(stderr, "Error: unknown option %s\n", argv[i]);
            exit(1);
        }
    }

    if (!pub_file || !in_file) {
        fprintf(stderr, "%s", usage);
        exit(1);
    }

    if (!out_file) {
        out_file = g_strdup_printf("%s.cpabe", in_file);
    }

    if (!policy) {
        policy = parse_policy_lang(suck_stdin());
    }
}

int main(int argc, char** argv) {
    bswabe_pub_t* pub;
    bswabe_cph_t* cph;
    int file_len;
    GByteArray* plt;
    GByteArray* cph_buf;
    GByteArray* aes_buf;
    element_t m;

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

    // Encrypt the file
    element_init_GT(m, pub->p);
    if (!(cph = bswabe_enc(pub, m, policy))) {
        printf("Error during encryption: %s\n", bswabe_error());
        core_clean();
        return 1;
    }
    free(policy);

    cph_buf = bswabe_cph_serialize(cph);
    bswabe_cph_free(cph);

    plt = suck_file(in_file);
    file_len = plt->len;
    aes_buf = aes_128_cbc_encrypt(plt, m);
    g_byte_array_free(plt, 1);
    element_clear(m);

    write_cpabe_file(out_file, cph_buf, file_len, aes_buf);

    g_byte_array_free(cph_buf, 1);
    g_byte_array_free(aes_buf, 1);

    if (!keep) {
        unlink(in_file);
    }

    core_clean();
    return 0;
}
