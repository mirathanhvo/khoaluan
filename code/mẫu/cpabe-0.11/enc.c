#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <relic.h>
#include <relic_test.h>
#include <arpa/inet.h> // để dùng htonl()
#define OPENSSL_API_COMPAT 0x10100000L

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
" -h, --help               print this message\n"
" -v, --version            print version information\n"
" -k, --keep-input-file    don't delete original file\n"
" -o, --output FILE        write resulting key to FILE\n"
" -d, --deterministic      use deterministic \"random\" numbers\n"
"                          (only for debugging)\n";

extern char* policy;

void encrypt_file(char* pub_file, char* in_file, char* out_file, char* policy) {
    /* 1. Khởi tạo RELIC và tham số pairing */
    if (core_init() != RLC_OK) {
        printf("Error initializing RELIC.\n");
        exit(1);
    }
    if (pc_param_set_any() != RLC_OK) {
        printf("Error setting pairing parameters.\n");
        core_clean();
        exit(1);
    }
    printf("Pairing parameters in encryption:\n");
    pc_param_print();  // Không truyền đối số

    /* 2. Đọc public key */
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
        printf("Error: Memory allocation failed for public key data.\n");
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
    bswabe_pub_t* pub = bswabe_pub_unserialize(pub_buf, 0);
    if (!pub) {
        printf("Error unserializing public key.\n");
        g_byte_array_free(pub_buf, TRUE);
        core_clean();
        exit(1);
    }
    g_byte_array_free(pub_buf, TRUE);
    printf("Public key loaded successfully (size: %ld bytes).\n", pub_len);

    // In ra các phần tử của public key sau unserialize
    printf("Public key element g in encryption:\n");
    ep_print(pub->g);
    printf("\nPublic key element gp in encryption:\n");
    ep2_print(pub->gp);  // Sửa ở đây: dùng ep2_print cho phần tử G2
    printf("\n");

    /* 3. Đọc file input */
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
        printf("Error: Memory allocation failed for input file.\n");
        fclose(in_fp);
        bswabe_pub_free(pub);
        core_clean();
        exit(1);
    }
    if (fread(in_data, 1, in_file_size, in_fp) != in_file_size) {
        printf("Error: Failed to read input file.\n");
        free(in_data);
        fclose(in_fp);
        bswabe_pub_free(pub);
        core_clean();
        exit(1);
    }
    fclose(in_fp);

    /* 4. Khởi tạo các biến bn_t và in ra order */
    bn_t key_rand, iv_rand, order;
    bn_null(key_rand);
    bn_null(iv_rand);
    bn_null(order);
    bn_new(key_rand);
    bn_new(iv_rand);
    bn_new(order);
    ep_curve_get_ord(order);
    printf("Order in encryption: ");
    bn_print(order);
    printf("\n");

    /* 5. Sinh số ngẫu nhiên và tính m = e(g, gp)^(key_rand) */
    bn_rand_mod(key_rand, order);
    gt_t m;
    gt_new(m);
    pc_map(m, pub->g, pub->gp);
    gt_exp(m, m, key_rand);

    /* Debug: In ra serialized m trước canonical hóa */
    printf("Before gt_norm, serialized m (enc): ");
    int temp_size = fp12_size_bin(m, 1);
    uint8_t *temp_buffer = malloc(temp_size);
    if (!temp_buffer) {
        printf("Error: Memory allocation failed for temp_buffer.\n");
        exit(1);
    }
    fp12_write_bin(temp_buffer, temp_size, m, 1);
    for (int i = 0; i < temp_size; i++) {
        printf("%02x", temp_buffer[i]);
    }
    printf("\n");
    free(temp_buffer);

    /* 6. Canonical hóa GT m và tính kích thước serialize mới */
    gt_norm(m);
    int gt_req_size = fp12_size_bin(m, 1);
    printf("gt_req_size after gt_norm = %d\n", gt_req_size);

    /* 7. Cấp phát bộ đệm với dung lượng an toàn: bổ sung thêm 128 byte dự phòng */
    int safe_size = gt_req_size + 128;  // tăng thêm dự phòng, có thể thử +128 hoặc +256
    uint8_t *buffer = malloc(safe_size);
    if (!buffer) {
        printf("Error: Memory allocation failed for GT buffer.\n");
        free(in_data);
        bswabe_pub_free(pub);
        bn_free(key_rand); bn_free(iv_rand); bn_free(order);
        gt_free(m);
        core_clean();
        exit(1);
    }
    /* Ghi phần tử GT đã canonical hóa vào bộ đệm */
    fp12_write_bin(buffer, safe_size, m, 1);
    printf("After gt_norm, serialized m (enc): ");
    for (int i = 0; i < gt_req_size; i++) {
        printf("%02x", buffer[i]);
    }
    printf("\n");

    /* 8. Sinh AES key bằng cách băm buffer (lấy 16 byte đầu) */
    uint8_t aes_key[16];
    unsigned int digest_len;
    EVP_Digest(buffer, gt_req_size, aes_key, &digest_len, EVP_sha256(), NULL);
    printf("AES key (enc): ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", aes_key[i]);
    }
    printf("\n");
    free(buffer);

    /* 9. Sinh IV từ iv_rand */
    bn_rand_mod(iv_rand, order);
    int iv_bn_len = bn_size_bin(iv_rand);
    uint8_t *iv_buf = malloc(iv_bn_len);
    if (!iv_buf) {
        printf("Error: Memory allocation failed for IV buffer.\n");
        free(in_data);
        bswabe_pub_free(pub);
        bn_free(key_rand); bn_free(iv_rand); bn_free(order);
        gt_free(m);
        core_clean();
        exit(1);
    }
    bn_write_bin(iv_buf, iv_bn_len, iv_rand);
    uint8_t hash_iv[32];
    EVP_Digest(iv_buf, iv_bn_len, hash_iv, &digest_len, EVP_sha256(), NULL);
    free(iv_buf);
    uint8_t iv[12];
    memcpy(iv, hash_iv, 12);

    /* 10. Mã hóa dữ liệu với AES-GCM */
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("Error: Failed to initialize AES context.\n");
        free(in_data);
        bswabe_pub_free(pub);
        bn_free(key_rand); bn_free(iv_rand); bn_free(order);
        gt_free(m);
        core_clean();
        exit(1);
    }
    uint8_t* encrypted_data = malloc(in_file_size + 16);
    if (!encrypted_data) {
        printf("Error: Memory allocation failed for encrypted data.\n");
        EVP_CIPHER_CTX_free(ctx);
        free(in_data);
        bswabe_pub_free(pub);
        bn_free(key_rand); bn_free(iv_rand); bn_free(order);
        gt_free(m);
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

    /* 11. CP-ABE mã hóa phần tử m theo policy */
    bswabe_cph_t* cph = bswabe_enc(pub, m, policy);
    if (!cph) {
        printf("CP-ABE encryption failed: %s\n", bswabe_error());
        free(in_data);
        free(encrypted_data);
        bswabe_pub_free(pub);
        bn_free(key_rand); bn_free(iv_rand); bn_free(order);
        gt_free(m);
        core_clean();
        exit(1);
    }
    GByteArray* cph_buf = bswabe_cph_serialize(cph);
    bswabe_cph_free(cph);
    gt_free(m);
    bn_free(key_rand); bn_free(iv_rand); bn_free(order);

    printf("DEBUG (enc): ciphertext_len = %d, CP-ABE ciphertext length = %u\n", ciphertext_len, cph_buf->len);
    long total_enc = sizeof(iv) + sizeof(tag) + HEADER_SIZE + ciphertext_len + cph_buf->len;
    printf("DEBUG (enc): expected total file size = %ld\n", total_enc);

    /* 12. Ghi dữ liệu đã mã hóa ra file output */
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
    fwrite(iv, 1, sizeof(iv), out_fp);           // Ghi IV (12 byte)
    fwrite(tag, 1, sizeof(tag), out_fp);           // Ghi tag (16 byte)
    uint32_t sym_len = htonl(ciphertext_len);      // Header cho AES ciphertext
    uint32_t abe_len = htonl(cph_buf->len);         // Header cho CP-ABE ciphertext
    fwrite(&sym_len, sizeof(uint32_t), 1, out_fp);
    fwrite(&abe_len, sizeof(uint32_t), 1, out_fp);
    fwrite(encrypted_data, 1, ciphertext_len, out_fp);
    fwrite(cph_buf->data, 1, cph_buf->len, out_fp);
    fclose(out_fp);

    /* 13. Clean up */
    free(in_data);
    free(encrypted_data);
    bswabe_pub_free(pub);
    g_byte_array_free(cph_buf, TRUE);
    core_clean();
}

int main(int argc, char** argv) {
    parse_args(argc, argv); // Hàm này cần được định nghĩa để lấy các đối số: pub_file, in_file, out_file, policy, keep, v.v.
    
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
