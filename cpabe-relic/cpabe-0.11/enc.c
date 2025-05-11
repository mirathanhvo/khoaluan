#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <relic/relic.h>
#include <openssl/evp.h>
#include <arpa/inet.h> // htonl()
#include <openssl/rand.h>
#include <unistd.h>

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
" -o, --output FILE        write resulting key to FILE\n\n";
void parse_args(int argc, char** argv) {
    int i;
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            printf("%s", usage); exit(0);
        } else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--version")) {
            printf(CPABE_VERSION, "-enc"); exit(0);
        } else if (!strcmp(argv[i], "-k") || !strcmp(argv[i], "--keep-input-file")) {
            keep = 1;
        } else if (!strcmp(argv[i], "-o") || !strcmp(argv[i], "--output")) {
            if (++i >= argc) die(usage);
            out_file = argv[i];
        } else if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--deterministic")) {
            uint8_t seed[20] = "deterministic_seed";
            rand_seed(seed, 20);
        } else if (!pub_file) {
            pub_file = argv[i];
        } else if (!in_file) {
            in_file = argv[i];
        } else if (!policy) {
            policy = parse_policy_lang(argv[i]);
        } else {
            die(usage);
        }
    }

    if (!pub_file || !in_file) die(usage);
    if (!out_file)
        out_file = g_strdup_printf("%s.cpabe", in_file);
    if (!policy)
        policy = parse_policy_lang(suck_stdin());
}

int main(int argc, char** argv) {
    parse_args(argc, argv);

    if (core_init() != RLC_OK || pc_param_set_any() != RLC_OK)
        die("RELIC initialization failed");

    bswabe_pub_t* pub = bswabe_pub_unserialize(suck_file(pub_file), 1);
    GByteArray* in_buf = suck_file(in_file);

    gt_t m;
    gt_null(m); gt_new(m);
    bswabe_cph_t* cph = bswabe_enc(pub, m, policy);
    if (!cph)
        die("Encryption failed: %s", bswabe_error());

    int m_len = gt_size_bin(m, 1);
    uint8_t* m_buf = malloc(m_len);
    gt_write_bin(m_buf, m_len, m, 1);

    uint8_t hash[32];
    EVP_Digest(m_buf, m_len, hash, NULL, EVP_sha256(), NULL);
    free(m_buf);

    uint8_t aes_key[16];
    memcpy(aes_key, hash, 16);

    uint8_t iv[12];
    RAND_bytes(iv, 12);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    uint8_t* ciphertext = malloc(in_buf->len + 16);
    int len, ciphertext_len;
    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, aes_key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, in_buf->data, in_buf->len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    uint8_t tag[16];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);

    GByteArray* cph_buf = bswabe_cph_serialize(cph);
    bswabe_cph_free(cph);
    gt_free(m);

    write_cpabe_file(out_file, cph_buf->data, cph_buf->len, ciphertext, ciphertext_len, iv, tag);

    g_byte_array_free(cph_buf, TRUE);
    g_byte_array_free(in_buf, TRUE);
    free(ciphertext);

    if (!keep)
        unlink(in_file);

    core_clean();
    return 0;
}