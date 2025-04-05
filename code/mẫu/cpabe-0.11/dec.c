#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <relic.h>
#include <arpa/inet.h> // để dùng ntohl()
#define OPENSSL_API_COMPAT 0x10100000L

#include <openssl/aes.h>
#include <openssl/evp.h>

#include "bswabe.h"
#include "common.h"

// Ensure the functions are declared if not already in bswabe.h
bswabe_prv_t* bswabe_prv_unserialize(bswabe_pub_t*, GByteArray*, int);
bswabe_cph_t* bswabe_cph_unserialize(bswabe_pub_t*, GByteArray*, int);

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

void decrypt_file(char* pub_file, char* prv_file, char* in_file, char* out_file) {
    // Initialize RELIC
    if (core_init() != RLC_OK) {
        core_clean();
        printf("Error initializing RELIC.\n");
        exit(1);
    }

    // Thiết lập các tham số pairing
    if (pc_param_set_any() != RLC_OK) {
        printf("Error setting pairing parameters.\n");
        core_clean();
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
    if (fread(pub_data, 1, pub_len, pub_fp) != pub_len) {
        printf("Error reading public key file.\n");
        free(pub_data);
        fclose(pub_fp);
        core_clean();
        exit(1);
    }
    fclose(pub_fp);

    GByteArray* pub_buf = g_byte_array_new_take(pub_data, pub_len);
    bswabe_pub_t* pub = bswabe_pub_unserialize(pub_buf, 1);
    if (!pub) {
        printf("Error unserializing public key.\n");
        free(pub_data);
        core_clean();
        exit(1);
    }

    // Read private key
    FILE* prv_fp = fopen(prv_file, "rb");
    if (!prv_fp) {
        printf("Error opening private key file.\n");
        bswabe_pub_free(pub);
        core_clean();
        exit(1);
    }
    GByteArray* prv_buf = g_byte_array_new();
    fseek(prv_fp, 0, SEEK_END);
    long prv_file_size = ftell(prv_fp);
    fseek(prv_fp, 0, SEEK_SET);
    g_byte_array_set_size(prv_buf, prv_file_size);
    fread(prv_buf->data, 1, prv_file_size, prv_fp);
    fclose(prv_fp);
    bswabe_prv_t* prv = bswabe_prv_unserialize(pub, prv_buf, 1);

    // Read input file
    size_t file_len;
    uint8_t *file_buf = suck_file(in_file, &file_len);
    if (!file_buf) {
        die("Error reading ciphertext file");
    }

    // Kiểm tra kích thước file có đủ dữ liệu không:
    size_t header_size = IV_SIZE + TAG_SIZE + 2 * sizeof(uint32_t) + AES_KEY_LEN;
    if (file_len < header_size) {
        die("File ciphertext quá ngắn, không hợp lệ.");
    }
    int offset = 0;

    // Đọc IV
    printf("Before IV: offset=%d, need=%d, file_len=%d\n", offset, IV_SIZE, (int)file_len);
    uint8_t iv[IV_SIZE];
    memcpy(iv, file_buf + offset, IV_SIZE);
    offset += IV_SIZE;

    // Đọc Tag
    printf("Before tag: offset=%d, need=%d, file_len=%d\n", offset, TAG_SIZE, (int)file_len);
    uint8_t tag[TAG_SIZE];
    memcpy(tag, file_buf + offset, TAG_SIZE);
    offset += TAG_SIZE;

    // Đọc kích thước AES-encrypted data và ABE ciphertext (uint32_t)
    uint32_t sym_len_net, abe_len_net;
    printf("Before sym_len: offset=%d, need=%d, file_len=%d\n", offset, (int)sizeof(uint32_t), (int)file_len);
    memcpy(&sym_len_net, file_buf + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    printf("Before abe_len: offset=%d, need=%d, file_len=%d\n", offset, (int)sizeof(uint32_t), (int)file_len);
    memcpy(&abe_len_net, file_buf + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    uint32_t sym_len = ntohl(sym_len_net);
    uint32_t abe_len = ntohl(abe_len_net);

    // Đọc AES-encrypted data (sym_len bytes)
    if (file_len < offset + sym_len) {
        die("File ciphertext quá ngắn cho phần AES-encrypted data.");
    }
    uint8_t* encrypted_data = malloc(sym_len);
    if (!encrypted_data) {
        die("Memory allocation failed for AES-encrypted data.");
    }
    memcpy(encrypted_data, file_buf + offset, sym_len);
    offset += sym_len;

    // Đọc CP-ABE ciphertext
    if (file_len < offset + abe_len) {
        die("File ciphertext quá ngắn cho CP-ABE ciphertext.");
    }
    GByteArray* cph_buf = g_byte_array_new();
    g_byte_array_append(cph_buf, file_buf + offset, abe_len);
    offset += abe_len;

    printf("DEBUG (dec): cph_buf->len = %u, expected = %u\n", cph_buf->len, abe_len);

    // Đọc AES key
    if (file_len < offset + AES_KEY_LEN) {
        die("File ciphertext không chứa đủ dữ liệu cho AES key.");
    }
    uint8_t aes_key_file[AES_KEY_LEN];
    memcpy(aes_key_file, file_buf + offset, AES_KEY_LEN);
    offset += AES_KEY_LEN;

    // Debug: in ra AES key đọc được từ file
    printf("AES key (dec read from file): ");
    for (int i = 0; i < AES_KEY_LEN; i++) {
        printf("%02x", aes_key_file[i]);
    }
    printf("\n");

    // Decrypt AES key with CP-ABE
    gt_t M;
    gt_null(M);
    gt_new(M);

    // Sử dụng cph_buf để unserialize CP-ABE ciphertext.
    // Lưu ý: truyền flag = 1 để _unserialize tự giải phóng cph_buf,
    // do đó không cần gọi g_byte_array_free(cph_buf, TRUE) sau này.
    bswabe_cph_t* cph = bswabe_cph_unserialize(pub, cph_buf, 1);

    if (!bswabe_dec(pub, prv, cph, M)) {
        fprintf(stderr, "ERROR: CP-ABE decryption failed! Your attributes do not satisfy the policy.\n");
        gt_free(M);  // tránh memory leak
        bswabe_cph_free(cph);
        bswabe_pub_free(pub);
        bswabe_prv_free(prv);
        core_clean();
        exit(1);
    }

    // M chứa e(pub->g_hat_alpha, s) * 1 = e(pub->g_hat_alpha, s)
    gt_norm(M); // Quan trọng!
    int m_len = gt_size_bin(M, 1);
    uint8_t* m_buf = malloc(m_len);
    if (!m_buf) {
        fprintf(stderr, "Memory allocation failed for m_buf.\n");
        free(file_buf);
        free(encrypted_data);
        bswabe_pub_free(pub);
        bswabe_prv_free(prv);
        gt_free(M);
        bswabe_cph_free(cph);
        core_clean();
        exit(1);
    }
    gt_write_bin(m_buf, m_len, M, 1);

    uint8_t hash[32];
    EVP_Digest(m_buf, m_len, hash, NULL, EVP_sha256(), NULL);
    uint8_t aes_key[16];
    memcpy(aes_key, hash, 16);

    free(m_buf);
    gt_free(M);

    // Debug: in ra giá trị AES key hash
    printf("AES key (dec computed): ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", aes_key[i]);
    }
    printf("\n");

    // Debug: in ra giá trị IV và Tag
    printf("IV: ");
    for (int i = 0;  i < 12; i++) {
        printf("%02x", iv[i]);
    }
    printf("\n");

    printf("Tag: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", tag[i]);
    }
    printf("\n");

    // Decrypt data with AES-GCM
    int aes_ciphertext_len = sym_len;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    uint8_t* decrypted_data = malloc(aes_ciphertext_len);
    int len, plaintext_len;

    EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, aes_key, iv);
    EVP_DecryptUpdate(ctx, decrypted_data, &len, encrypted_data, aes_ciphertext_len);
    plaintext_len = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
    if (EVP_DecryptFinal_ex(ctx, decrypted_data + len, &len) <= 0) {
        printf("AES-GCM authentication failed! Possible incorrect key.\n");
        EVP_CIPHER_CTX_free(ctx);
        free(file_buf);
        free(encrypted_data);
        free(decrypted_data);
        bswabe_pub_free(pub);
        bswabe_prv_free(prv);
        core_clean();
        exit(1);
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    // Write decrypted data to output file
    FILE* out_fp = fopen(out_file, "wb");
    if (!out_fp) {
        printf("Error opening output file.\n");
        free(file_buf);
        free(encrypted_data);
        free(decrypted_data);
        bswabe_pub_free(pub);
        bswabe_prv_free(prv);
        core_clean();
        exit(1);
    }
    fwrite(decrypted_data, 1, plaintext_len, out_fp);
    fclose(out_fp);

    // Clean up
    free(file_buf);
    free(encrypted_data);
    free(decrypted_data);
    bswabe_pub_free(pub);
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