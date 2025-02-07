#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <relic.h>
#include <relic_test.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

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
            if (i + 1 < argc) {
                out_file = argv[++i];
            } else {
                printf("Error: Missing output file argument.\n");
                exit(1);
            }
        } else if (argv[i][0] != '-') {
            if (!pub_file) {
                pub_file = argv[i];
            } else if (!in_file) {
                in_file = argv[i];
            } else if (!policy) {
                policy = argv[i];
            } else {
                printf("Error: Too many arguments.\n");
                exit(1);
            }
        } else {
            printf("Error: Unknown option %s.\n", argv[i]);
            exit(1);
        }
    }

    if (!pub_file || !in_file) {
        printf("Error: Missing required arguments.\n");
        exit(1);
    }
}

void encrypt_file(char* pub_file, char* in_file, char* out_file, char* policy) {
    // Initialize RELIC
    if (core_init() != RLC_OK) {
        core_clean();
        printf("Error initializing RELIC.\n");
        exit(1);
    }

    // Read public key
    FILE* pub_fp = fopen(pub_file, "r");
    if (!pub_fp) {
        printf("Error opening public key file.\n");
        core_clean();
        exit(1);
    }
    g1_t pk;
    g1_null(pk);
    g1_new(pk);
    g1_read(pub_fp, pk);
    fclose(pub_fp);

    // Read input file
    FILE* in_fp = fopen(in_file, "r");
    if (!in_fp) {
        printf("Error opening input file.\n");
        core_clean();
        exit(1);
    }
    fseek(in_fp, 0, SEEK_END);
    long in_file_size = ftell(in_fp);
    fseek(in_fp, 0, SEEK_SET);
    uint8_t* in_data = malloc(in_file_size);
    fread(in_data, 1, in_file_size, in_fp);
    fclose(in_fp);

    // Generate random AES key
    uint8_t aes_key[16];
    RAND_bytes(aes_key, sizeof(aes_key));

    // Encrypt data with AES-GCM
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    uint8_t iv[12];
    RAND_bytes(iv, sizeof(iv));
    uint8_t* encrypted_data = malloc(in_file_size + 16); // Allocate extra space for padding
    int len, ciphertext_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, aes_key, iv);
    EVP_EncryptUpdate(ctx, encrypted_data, &len, in_data, in_file_size);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, encrypted_data + len, &len);
    ciphertext_len += len;

    uint8_t tag[16];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);

    // Encrypt AES key with CP-ABE
    element_t m;
    element_init_GT(m, pk);
    element_from_hash(m, aes_key, sizeof(aes_key));
    bswabe_cph_t* cph = bswabe_enc(pk, m, policy);
    GByteArray* cph_buf = bswabe_cph_serialize(cph);
    bswabe_cph_free(cph);
    element_clear(m);

    // Write encrypted data to output file
    FILE* out_fp = fopen(out_file, "w");
    if (!out_fp) {
        printf("Error opening output file.\n");
        core_clean();
        exit(1);
    }
    fwrite(iv, 1, sizeof(iv), out_fp); // Write IV
    fwrite(tag, 1, sizeof(tag), out_fp); // Write GCM tag
    fwrite(encrypted_data, 1, ciphertext_len, out_fp); // Write ciphertext
    fwrite(cph_buf->data, 1, cph_buf->len, out_fp); // Write CP-ABE encrypted AES key
    fclose(out_fp);

    // Clean up
    free(in_data);
    free(encrypted_data);
    g1_free(pk);
    g_byte_array_free(cph_buf, 1);
    core_clean();
}

int main(int argc, char** argv) {
    parse_args(argc, argv);

    if (!out_file) {
        out_file = g_strdup_printf("%s.cpabe", in_file);
    }

    if (!policy) {
        printf("Enter policy: ");
        size_t len = 0;
        getline(&policy, &len, stdin);
    }

    encrypt_file(pub_file, in_file, out_file, policy);

    if (!keep) {
        unlink(in_file);
    }

    return 0;
}
