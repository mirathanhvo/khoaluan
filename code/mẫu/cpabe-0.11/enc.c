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
        printf("Error initializing RELIC.\n");
        exit(1);
    }

    // Read public key
    FILE* pub_fp = fopen(pub_file, "rb");
    if (!pub_fp) {
        printf("Error opening public key file.\n");
        core_clean();
        exit(1);
    }
    fseek(pub_fp, 0, SEEK_END);
    long pub_len = ftell(pub_fp);
    fseek(pub_fp, 0, SEEK_SET);
    uint8_t* pub_data = malloc(pub_len);
    if (!pub_data) {
        printf("Error: Memory allocation failed.\n");
        fclose(pub_fp);
        core_clean();
        exit(1);
    }
    if (fread(pub_data, 1, pub_len, pub_fp) != pub_len) {
        printf("Error: Failed to read public key file.\n");
        free(pub_data);
        fclose(pub_fp);
        core_clean();
        exit(1);
    }
    fclose(pub_fp);

    GByteArray* pub_buf = g_byte_array_new_take(pub_data, pub_len);
    bswabe_pub_t* pub = bswabe_pub_unserialize(pub_buf);
    g_byte_array_free(pub_buf, TRUE);

    // Read input file
    FILE* in_fp = fopen(in_file, "rb");
    if (!in_fp) {
        printf("Error opening input file.\n");
        bswabe_pub_free(pub);
        core_clean();
        exit(1);
    }
    fseek(in_fp, 0, SEEK_END);
    long in_file_size = ftell(in_fp);
    fseek(in_fp, 0, SEEK_SET);
    uint8_t* in_data = malloc(in_file_size);
    if (!in_data) {
        printf("Error: Memory allocation failed.\n");
        fclose(in_fp);
        bswabe_pub_free(pub);
        core_clean();
        exit(1);
    }
    fread(in_data, 1, in_file_size, in_fp);
    fclose(in_fp);

    // Generate random AES key
    uint8_t aes_key[16];
    bn_t rand_val, order;
    bn_null(rand_val);
    bn_null(order);
    bn_new(rand_val);
    bn_new(order);
    ep_curve_get_ord(order);
    bn_rand_mod(rand_val, order);
    bn_write_bin(aes_key, sizeof(aes_key), rand_val);

    // Encrypt data with AES-GCM
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("Error: Failed to initialize AES context.\n");
        free(in_data);
        bswabe_pub_free(pub);
        core_clean();
        exit(1);
    }
    uint8_t iv[12];
    bn_rand_mod(rand_val, order);
    bn_write_bin(iv, sizeof(iv), rand_val);
    uint8_t* encrypted_data = malloc(in_file_size + 16); // Allocate extra space for padding
    if (!encrypted_data) {
        printf("Error: Memory allocation failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        free(in_data);
        bswabe_pub_free(pub);
        core_clean();
        exit(1);
    }
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
    gt_t m;
    gt_new(m);
    pp_map_oatep_k12(m, pub->g, pub->gp);
    gt_exp(m, m, rand_val);
    bswabe_cph_t* cph = bswabe_enc(pub, m, policy);
    if (!cph) {
        printf("CP-ABE encryption failed: %s\n", bswabe_error());
        free(in_data);
        free(encrypted_data);
        bswabe_pub_free(pub);
        core_clean();
        exit(1);
    }
    GByteArray* cph_buf = bswabe_cph_serialize(cph);
    bswabe_cph_free(cph);
    gt_free(m);
    bn_free(rand_val);
    bn_free(order);

    // Write encrypted data to output file
    FILE* out_fp = fopen(out_file, "wb");
    if (!out_fp) {
        printf("Error opening output file.\n");
        free(in_data);
        free(encrypted_data);
        bswabe_pub_free(pub);
        g_byte_array_free(cph_buf, TRUE);
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
    bswabe_pub_free(pub);
    g_byte_array_free(cph_buf, TRUE);
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
