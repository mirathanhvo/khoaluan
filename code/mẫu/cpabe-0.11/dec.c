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
    FILE* in_fp = fopen(in_file, "rb");
    if (!in_fp) {
        printf("Error opening input file.\n");
        bswabe_pub_free(pub);
        bswabe_prv_free(prv);
        core_clean();
        exit(1);
    }
    fseek(in_fp, 0, SEEK_END);
    long in_file_size = ftell(in_fp);
    fseek(in_fp, 0, SEEK_SET);
    uint8_t* in_data = malloc(in_file_size);
    fread(in_data, 1, in_file_size, in_fp);
    fclose(in_fp);

    // Đọc IV (12 byte)
    uint8_t iv[12];
    memcpy(iv, in_data, sizeof(iv));

    // Đọc GCM tag (16 byte)
    uint8_t tag[16];
    memcpy(tag, in_data + sizeof(iv), sizeof(tag));

    // Đọc header (8 byte)
    uint32_t sym_len, abe_len;
    memcpy(&sym_len, in_data + sizeof(iv) + sizeof(tag), sizeof(uint32_t));
    memcpy(&abe_len, in_data + sizeof(iv) + sizeof(tag) + sizeof(uint32_t), sizeof(uint32_t));

    // Chuyển từ network byte order về host order
    sym_len = ntohl(sym_len);
    abe_len = ntohl(abe_len);

    // Thêm debug print:
    printf("DEBUG (dec): sym_len = %u, abe_len = %u\n", sym_len, abe_len);

    long expected_total = sizeof(iv) + sizeof(tag) + HEADER_SIZE + sym_len + abe_len;
    printf("DEBUG (dec): expected total file size = %ld, actual file size = %ld\n", expected_total, in_file_size);

    // Phần AES ciphertext nằm ngay sau header (8 byte)
    uint8_t* encrypted_data = in_data + sizeof(iv) + sizeof(tag) + HEADER_SIZE;
    long encrypted_data_len = sym_len;  // dùng sym_len làm độ dài ciphertext AES

    // Phần CP-ABE ciphertext nằm sau phần AES ciphertext
    long cph_data_offset = sizeof(iv) + sizeof(tag) + HEADER_SIZE + sym_len;
    GByteArray* cph_buf = g_byte_array_new();
    g_byte_array_append(cph_buf, in_data + cph_data_offset, abe_len);

    // Debug print
    printf("DEBUG (dec): cph_buf->len = %u, expected = %u\n", cph_buf->len, abe_len);

    // Sử dụng cph_buf để unserialize CP-ABE ciphertext.
    // Lưu ý: truyền flag = 1 để _unserialize tự giải phóng cph_buf,
    // do đó không cần gọi g_byte_array_free(cph_buf, TRUE) sau này.
    bswabe_cph_t* cph = bswabe_cph_unserialize(pub, cph_buf, 1);

    // Decrypt AES key with CP-ABE
    gt_t m;
    gt_null(m);
    gt_new(m);

    if (!bswabe_dec(pub, prv, cph, m)) {
        fprintf(stderr, "ERROR: CP-ABE decryption failed! Your attributes do not satisfy the policy.\n");
        gt_free(m);  // tránh memory leak
        bswabe_cph_free(cph);
        bswabe_pub_free(pub);
        bswabe_prv_free(prv);
        core_clean();
        exit(1);
    }

    // Sau khi bswabe_dec(..., m) thành công
    int size_before = fp12_size_bin(m, 1);
    uint8_t *buf_before = malloc(size_before);
    fp12_write_bin(buf_before, size_before, m, 1);
    printf("Before gt_norm, serialized m (dec): ");
    for (int i = 0; i < size_before; i++) {
        printf("%02x", buf_before[i]);
    }
    printf("\n");
    free(buf_before);

    gt_norm(m);

    int gt_req_size = fp12_size_bin(m, 1);
    uint8_t *buf_after = malloc(gt_req_size);
    fp12_write_bin(buf_after, gt_req_size, m, 1);
    printf("After gt_norm, serialized m (dec): ");
    for (int i = 0; i < gt_req_size; i++) {
        printf("%02x", buf_after[i]);
    }
    printf("\n");
    free(buf_after);

    // Tính kích thước và cấp phát buffer cho phần tử m
    gt_req_size = fp12_size_bin(m, 1);
    uint8_t *buffer = malloc(gt_req_size);
    if (!buffer) {
        die("Memory allocation error for GT buffer.\n");
    }
    fp12_write_bin(buffer, gt_req_size, m, 1);

    // Debug: in ra giá trị serialized của m
    printf("Serialized m (dec): ");
    for (int i = 0; i < gt_req_size; i++) {
        printf("%02x", buffer[i]);
    }
    printf("\n");

    // Băm buffer để tạo AES key
    uint8_t hash[32];
    unsigned int digest_len;
    EVP_Digest(buffer, gt_req_size, hash, &digest_len, EVP_sha256(), NULL);
    uint8_t aes_key[16];
    memcpy(aes_key, hash, 16);

    // Debug: in ra giá trị AES key hash
    printf("AES key (dec): ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", aes_key[i]);
    }
    printf("\n");

    free(buffer);
    gt_free(m);
    bswabe_cph_free(cph);

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
        printf("AES-GCM authentication failed! Possible incorrect key.\n");
        EVP_CIPHER_CTX_free(ctx);
        free(in_data);
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
        free(in_data);
        free(decrypted_data);
        bswabe_pub_free(pub);
        bswabe_prv_free(prv);
        core_clean();
        exit(1);
    }
    fwrite(decrypted_data, 1, plaintext_len, out_fp);
    fclose(out_fp);

    // Clean up
    free(in_data);
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
