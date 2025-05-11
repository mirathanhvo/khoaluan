#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <relic/relic.h>
#include <openssl/evp.h>
#include "bswabe.h"
#include "common.h"

char* usage =
"Usage: cpabe-dec [OPTION ...] PUB_KEY PRIV_KEY FILE\n"
"\n"
"Decrypt FILE using private key PRIV_KEY and public key PUB_KEY.\n"
"If FILE ends with .cpabe, the output will be FILE without that extension.\n"
"Otherwise, output will overwrite FILE unless -o is specified.\n"
"\n"
" -h, --help               print this message\n"
" -v, --version            print version information\n"
" -k, --keep-input-file    don't delete original file\n"
" -o, --output FILE        write output to FILE\n\n";

void parse_args(int argc, char** argv) {
    int i;
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            printf("%s", usage); exit(0);
        } else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--version")) {
            printf(CPABE_VERSION, "-dec"); exit(0);
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
        } else if (!prv_file) {
            prv_file = argv[i];
        } else if (!in_file) {
            in_file = argv[i];
        } else {
            die(usage);
        }
    }

    if (!pub_file || !prv_file || !in_file)
        die(usage);

    if (!out_file) {
        if (strlen(in_file) > 6 && !strcmp(in_file + strlen(in_file) - 6, ".cpabe"))
            out_file = g_strndup(in_file, strlen(in_file) - 6);
        else
            out_file = strdup(in_file);
    }

    if (keep && !strcmp(in_file, out_file))
        die("cannot keep input file when decrypting file in place (try -o)\n");
}

int main(int argc, char** argv) {
    parse_args(argc, argv);

    if (core_init() != RLC_OK || pc_param_set_any() != RLC_OK)
        die("RELIC initialization failed");

    bswabe_pub_t* pub = bswabe_pub_unserialize(suck_file(pub_file), 1);
    bswabe_prv_t* prv = bswabe_prv_unserialize(pub, suck_file(prv_file), 1);
        

    uint8_t *cph_buf_raw, *aes_buf, iv[12], tag[16];
    int cph_len, aes_len;
    read_cpabe_file(in_file, &cph_buf_raw, &cph_len, &aes_buf, &aes_len, iv, tag);

    GByteArray* cph_buf = g_byte_array_new();
    g_byte_array_append(cph_buf, cph_buf_raw, cph_len);
    bswabe_cph_t* cph = bswabe_cph_unserialize(pub, cph_buf, 0);
    g_byte_array_free(cph_buf, TRUE);
    free(cph_buf_raw);

    debug_cph_cs(cph);
    
    gt_t m;
    gt_null(m); gt_new(m);
    if (!bswabe_dec(pub, prv, cph, m)) {
        fprintf(stderr, "Decryption failed: attributes do not satisfy policy.\n");

        // Safely free resources
        if (prv) bswabe_prv_free(prv);
        if (pub) bswabe_pub_free(pub);
        if (cph) bswabe_cph_free(cph);

        core_clean();
        return 1;
    }
    gt_norm(m);

    int m_len = gt_size_bin(m, 1);
    uint8_t* m_buf = malloc(m_len);
    gt_write_bin(m_buf, m_len, m, 1);

    uint8_t hash[32];
    EVP_Digest(m_buf, m_len, hash, NULL, EVP_sha256(), NULL);
    uint8_t aes_key[16];
    memcpy(aes_key, hash, 16);
    free(m_buf);
    gt_free(m);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    uint8_t* plaintext = malloc(aes_len);
    int len, pt_len;

    EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, aes_key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &len, aes_buf, aes_len);
    pt_len = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0)
        die("AES-GCM authentication failed");
    pt_len += len;
    EVP_CIPHER_CTX_free(ctx);
    free(aes_buf);

    spit_file(out_file, plaintext, pt_len, 1);
    if (!keep)
        unlink(in_file);

    bswabe_pub_free(pub);
    bswabe_prv_free(prv);
    core_clean();
    return 0;
}