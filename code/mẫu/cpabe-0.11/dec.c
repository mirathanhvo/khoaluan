#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <relic.h>
#include <openssl/aes.h>
#include <openssl/evp.h>

#include "bswabe.h"
#include "common.h"

char* usage =
"Usage: cpabe-dec [OPTION ...] PUB_KEY PRIV_KEY FILE\n"
"\n"
"Decrypt FILE using private key PRIV_KEY and assuming public key\n"
"PUB_KEY. If the name of FILE is X.cpabe, the decrypted file will\n"
"be written as X and FILE will be removed. Otherwise the file will be\n"
"decrypted in place. Use of the -o option overrides this\n"
"behavior.\n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help               print this message\n\n"
" -v, --version            print version information\n\n"
" -k, --keep-input-file    don't delete original file\n\n"
" -o, --output FILE        write output to FILE\n\n"
" -d, --deterministic      use deterministic \"random\" numbers\n"
"                          (only for debugging)\n\n"
/* " -s, --no-opt-sat         pick an arbitrary way of satisfying the policy\n" */
/* "                          (only for performance comparison)\n\n" */
/* " -n, --naive-dec          use slower decryption algorithm\n" */
/* "                          (only for performance comparison)\n\n" */
/* " -f, --flatten            use slightly different decryption algorithm\n" */
/* "                          (may result in higher or lower performance)\n\n" */
/* " -r, --report-ops         report numbers of group operations\n" */
/* "                          (only for performance evaluation)\n\n" */
"";

char* pub_file   = 0;
char* prv_file   = 0;
char* in_file    = 0;
char* out_file   = 0;
int   keep       = 0;

void parse_args(int argc, char** argv) {
    int i;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            printf("%s", usage);
            exit(0);
        } else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--version")) {
            printf("cpabe-dec version 1.0\n");
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
            } else if (!prv_file) {
                prv_file = argv[i];
            } else if (!in_file) {
                in_file = argv[i];
            } else {
                printf("Error: Too many arguments.\n");
                exit(1);
            }
        } else {
            printf("Error: Unknown option %s.\n", argv[i]);
            exit(1);
        }
    }

    if (!pub_file || !prv_file || !in_file) {
        printf("Error: Missing required arguments.\n");
        exit(1);
    }
}

void decrypt_file(char* pub_file, char* prv_file, char* in_file, char* out_file) {
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

    // Read private key
    FILE* prv_fp = fopen(prv_file, "r");
    if (!prv_fp) {
        printf("Error opening private key file.\n");
        core_clean();
        exit(1);
    }
    bswabe_prv_t* prv = bswabe_prv_unserialize(prv_fp);
    fclose(prv_fp);

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

    // Extract IV, GCM tag, ciphertext, and CP-ABE encrypted AES key from input file
    uint8_t iv[12];
    uint8_t tag[16];
    memcpy(iv, in_data, sizeof(iv));
    memcpy(tag, in_data + sizeof(iv), sizeof(tag));
    uint8_t* encrypted_data = in_data + sizeof(iv) + sizeof(tag);
    long encrypted_data_len = in_file_size - sizeof(iv) - sizeof(tag) - cph_buf->len;

    // Deserialize CP-ABE encrypted AES key
    GByteArray* cph_buf = g_byte_array_new();
    g_byte_array_append(cph_buf, in_data + sizeof(iv) + sizeof(tag) + encrypted_data_len, cph_buf->len);
    bswabe_cph_t* cph = bswabe_cph_unserialize(cph_buf, 1);

    // Decrypt AES key with CP-ABE
    element_t m;
    element_init_GT(m, pk);
    if (!bswabe_dec(m, cph, prv)) {
        printf("Error decrypting AES key with CP-ABE.\n");
        core_clean();
        exit(1);
    }
    uint8_t aes_key[16];
    element_to_bytes(aes_key, m);
    element_clear(m);
    bswabe_cph_free(cph);
    g_byte_array_free(cph_buf, 1);

    // Decrypt data with AES-GCM
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    uint8_t* decrypted_data = malloc(encrypted_data_len);
    int len, plaintext_len;

    EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, aes_key, iv);
    EVP_DecryptUpdate(ctx, decrypted_data, &len, encrypted_data, encrypted_data_len);
    plaintext_len = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
    if (EVP_DecryptFinal_ex(ctx, decrypted_data + len, &len) <= 0) {
        printf("Error decrypting data with AES-GCM.\n");
        core_clean();
        exit(1);
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    // Write decrypted data to output file
    FILE* out_fp = fopen(out_file, "w");
    if (!out_fp) {
        printf("Error opening output file.\n");
        core_clean();
        exit(1);
    }
    fwrite(decrypted_data, 1, plaintext_len, out_fp);
    fclose(out_fp);

    // Clean up
    free(in_data);
    free(decrypted_data);
    g1_free(pk);
    bswabe_prv_free(prv);
    core_clean();
}

int main(int argc, char** argv) {
    parse_args(argc, argv);

    if (!out_file) {
        out_file = g_strdup_printf("%s.dec", in_file);
    }

    decrypt_file(pub_file, prv_file, in_file, out_file);

    if (!keep) {
        unlink(in_file);
    }

    return 0;
	
}
