#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <relic.h>
#include <relic_test.h>
#include <arpa/inet.h> // htonl()

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

    /* 4. Gọi bswabe_enc => CP-ABE tự sinh s và m */
    gt_t m;
    gt_new(m);
    bswabe_cph_t* cph = bswabe_enc(pub, m, policy);
    if (!cph || !cph->p) {
        fprintf(stderr, "ERROR: Failed to build ciphertext policy tree. Check policy syntax!\n");
        free(in_data);
        bswabe_pub_free(pub);
        gt_free(m);
        core_clean();
        exit(1);
    }

    /* 5. Dùng m để tạo AES key */
    gt_norm(m); // chuẩn hoá GT element
    int m_len = gt_size_bin(m, 1);
    uint8_t* m_buf = malloc(m_len);
    if (!m_buf) {
        fprintf(stderr, "Memory allocation failed for m_buf.\n");
        free(in_data);
        bswabe_pub_free(pub);
        gt_free(m);
        bswabe_cph_free(cph);
        core_clean();
        exit(1);
    }
    gt_write_bin(m_buf, m_len, m, 1);

    // Băm m_buf -> lấy 16 byte đầu làm aes_key
    uint8_t hash[32];
    unsigned int digest_len;
    EVP_Digest(m_buf, m_len, hash, &digest_len, EVP_sha256(), NULL);
    uint8_t aes_key[16];
    memcpy(aes_key, hash, 16);

    free(m_buf);
    printf("AES key (enc, pack=1): ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", aes_key[i]);
    }
    printf("\n");

    /* 6. Sinh IV từ iv_rand */
    bn_t iv_rand, order;
    bn_null(iv_rand);
    bn_null(order);
    bn_new(iv_rand);
    bn_new(order);
    ep_curve_get_ord(order);
    bn_rand_mod(iv_rand, order);
    int iv_bn_len = bn_size_bin(iv_rand);
    uint8_t *iv_buf = malloc(iv_bn_len);
    if (!iv_buf) {
        printf("Error: Memory allocation failed for IV buffer.\n");
        free(in_data);
        bswabe_pub_free(pub);
        bn_free(iv_rand); bn_free(order);
        gt_free(m);
        bswabe_cph_free(cph);
        core_clean();
        exit(1);
    }
    bn_write_bin(iv_buf, iv_bn_len, iv_rand);
    uint8_t hash_iv[32];
    EVP_Digest(iv_buf, iv_bn_len, hash_iv, &digest_len, EVP_sha256(), NULL);
    free(iv_buf);
    uint8_t iv[12];
    memcpy(iv, hash_iv, 12);

    /* 7. Mã hóa dữ liệu với AES-GCM */
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("Error: Failed to initialize AES context.\n");
        free(in_data);
        bswabe_pub_free(pub);
        bn_free(iv_rand); bn_free(order);
        gt_free(m);
        bswabe_cph_free(cph);
        core_clean();
        exit(1);
    }
    uint8_t* encrypted_data = malloc(in_file_size + 16);
    if (!encrypted_data) {
        printf("Error: Memory allocation failed for encrypted data.\n");
        EVP_CIPHER_CTX_free(ctx);
        free(in_data);
        bswabe_pub_free(pub);
        bn_free(iv_rand); bn_free(order);
        gt_free(m);
        bswabe_cph_free(cph);
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

    /* 8. Serialize CP-ABE ciphertext */
    GByteArray* cph_buf = bswabe_cph_serialize(cph);
    bswabe_cph_free(cph);
    gt_free(m);
    bn_free(iv_rand); bn_free(order);

    printf("DEBUG (enc): ciphertext_len = %d, CP-ABE ciphertext length = %u\n", ciphertext_len, cph_buf->len);
    long total_enc = sizeof(iv) + sizeof(tag) + HEADER_SIZE + ciphertext_len + cph_buf->len;
    printf("DEBUG (enc): expected total file size = %ld\n", total_enc);

    /* 9. Ghi dữ liệu đã mã hóa ra file output */
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

    // Ghi IV, Tag, và các giá trị cần thiết ra file output
    fwrite(iv, 1, sizeof(iv), out_fp);           // Ghi IV (12 byte)
    fwrite(tag, 1, sizeof(tag), out_fp);         // Ghi tag (16 byte)
    uint32_t sym_len = htonl(ciphertext_len);    // Header cho AES ciphertext
    uint32_t abe_len = htonl(cph_buf->len);      // Header cho CP-ABE ciphertext
    fwrite(&sym_len, sizeof(uint32_t), 1, out_fp);
    fwrite(&abe_len, sizeof(uint32_t), 1, out_fp);
    fwrite(encrypted_data, 1, ciphertext_len, out_fp);
    fwrite(cph_buf->data, 1, cph_buf->len, out_fp);

    // Sử dụng lại AES key đã tính ở bước 5 (đã lưu trong biến 'aes_key')
    printf("AES key (enc, final): ");
    for (int i = 0; i < AES_KEY_LEN; i++) {
        printf("%02x", aes_key[i]);
    }
    printf("\n");

    // Ghi AES key đã dùng cho AES-GCM vào file ciphertext
    fwrite(aes_key, 1, AES_KEY_LEN, out_fp);

    fclose(out_fp);

    /* 10. Clean up */
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
