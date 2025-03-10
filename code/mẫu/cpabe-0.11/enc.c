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
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help               print this message\n\n"
" -v, --version            print version information\n\n"
" -k, --keep-input-file    don't delete original file\n\n"
" -o, --output FILE        write resulting key to FILE\n\n"
" -d, --deterministic      use deterministic \"random\" numbers\n"
"                          (only for debugging)\n\n"
"";

extern char* policy;

void encrypt_file(char* pub_file, char* in_file, char* out_file, char* policy) {
    // Initialize RELIC
    if (core_init() != RLC_OK) {
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
    bswabe_pub_t* pub = bswabe_pub_unserialize(pub_buf, 0);  // Không giải phóng pub_buf bên trong hàm
    g_byte_array_free(pub_buf, TRUE);  // Tự giải phóng sau đó

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

    // Khai báo và khởi tạo các biến bn_t riêng cho AES key và IV
    bn_t key_rand, iv_rand, order;
    bn_null(key_rand);
    bn_null(iv_rand);
    bn_null(order);
    bn_new(key_rand);
    bn_new(iv_rand);
    bn_new(order);
    ep_curve_get_ord(order);

    // Sinh AES key từ key_rand (sinh r)
    bn_rand_mod(key_rand, order);

    // --- Thay đổi ở đây ---
    // Thay vì sinh AES key trực tiếp từ key_rand, ta tính m = e(g, gp)^(key_rand)
    gt_t m;
    gt_new(m);
    pc_map(m, pub->g, pub->gp);
    gt_exp(m, m, key_rand);

    // Debug: In ra giá trị serialized của m trước khi canonical hóa
    printf("Before gt_norm, serialized m (enc): ");
    int temp_size = fp12_size_bin(m, 1);
    uint8_t *temp_buffer = malloc(temp_size);
    fp12_write_bin(temp_buffer, temp_size, m, 1);
    for (int i = 0; i < temp_size; i++) {
        printf("%02x", temp_buffer[i]);
    }
    printf("\n");
    free(temp_buffer);

    gt_norm(m);

    // Chuyển phần tử GT m sang dạng nhị phân với pack = 1
    int gt_req_size = fp12_size_bin(m, 1);
    uint8_t *buffer = malloc(gt_req_size);
    if (!buffer) {
        printf("Error: Memory allocation failed.\n");
        free(in_data);
        bswabe_pub_free(pub);
        bn_free(key_rand);
        bn_free(iv_rand);
        bn_free(order);
        gt_free(m);
        core_clean();
        exit(1);
    }
    fp12_write_bin(buffer, gt_req_size, m, 1);

    // Debug: In ra giá trị serialized của m sau khi canonical hóa
    printf("After gt_norm, serialized m (enc): ");
    for (int i = 0; i < gt_req_size; i++) {
        printf("%02x", buffer[i]);
    }
    printf("\n");

    // Sinh AES key bằng cách băm buffer (lấy 16 byte đầu)
    uint8_t aes_key[16];
    unsigned int digest_len;
    EVP_Digest(buffer, gt_req_size, aes_key, &digest_len, EVP_sha256(), NULL);
    
    // Debug: In ra giá trị AES key hash (enc)
    printf("AES key (enc): ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", aes_key[i]);
    }
    printf("\n");

    free(buffer);
    // --- Kết thúc thay đổi ---

    // Sinh IV từ iv_rand
    bn_rand_mod(iv_rand, order);
    int iv_bn_len = bn_size_bin(iv_rand);
    uint8_t *iv_buf = malloc(iv_bn_len);
    if (!iv_buf) {
        printf("Error: Memory allocation failed.\n");
        free(in_data);
        bswabe_pub_free(pub);
        bn_free(key_rand);
        bn_free(iv_rand);
        bn_free(order);
        gt_free(m);
        core_clean();
        exit(1);
    }
    bn_write_bin(iv_buf, iv_bn_len, iv_rand);

    // Băm iv_buf bằng SHA-256 và lấy 12 byte đầu làm IV
    uint8_t hash_iv[32];
    unsigned int hash_len;
    EVP_Digest(iv_buf, iv_bn_len, hash_iv, &hash_len, EVP_sha256(), NULL);
    free(iv_buf);

    uint8_t iv[12];
    memcpy(iv, hash_iv, 12);

    // Encrypt data with AES-GCM
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("Error: Failed to initialize AES context.\n");
        free(in_data);
        bswabe_pub_free(pub);
        bn_free(key_rand);
        bn_free(iv_rand);
        bn_free(order);
        gt_free(m);
        core_clean();
        exit(1);
    }
    uint8_t* encrypted_data = malloc(in_file_size + 16); // Allocate extra space for padding
    if (!encrypted_data) {
        printf("Error: Memory allocation failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        free(in_data);
        bswabe_pub_free(pub);
        bn_free(key_rand);
        bn_free(iv_rand);
        bn_free(order);
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

    // CP-ABE mã hóa phần tử m (đảm bảo bên giải mã dùng đúng quy trình để tái tạo m và tính lại aes_key)
    bswabe_cph_t* cph = bswabe_enc(pub, m, policy);
    if (!cph) {
        printf("CP-ABE encryption failed: %s\n", bswabe_error());
        free(in_data);
        free(encrypted_data);
        bswabe_pub_free(pub);
        bn_free(key_rand);
        bn_free(iv_rand);
        bn_free(order);
        gt_free(m);
        core_clean();
        exit(1);
    }
    GByteArray* cph_buf = bswabe_cph_serialize(cph);
    bswabe_cph_free(cph);
    // Giải phóng m và các biến liên quan
    gt_free(m);
    bn_free(key_rand);
    bn_free(iv_rand);
    bn_free(order);

    // Debug print cho CP-ABE ciphertext
    printf("DEBUG (enc): ciphertext_len = %d, CP-ABE ciphertext length = %u\n", ciphertext_len, cph_buf->len);
    long total_enc = sizeof(iv) + sizeof(tag) + HEADER_SIZE + ciphertext_len + cph_buf->len;
    printf("DEBUG (enc): expected total file size = %ld\n", total_enc);

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

    // Ghi IV (12 byte)
    fwrite(iv, 1, sizeof(iv), out_fp);
    // Ghi GCM tag (16 byte)
    fwrite(tag, 1, sizeof(tag), out_fp);

    // Tạo header: 4 byte cho AES ciphertext length và 4 byte cho CP-ABE ciphertext length
    uint32_t sym_len = ciphertext_len;          // độ dài AES ciphertext
    uint32_t abe_len = cph_buf->len;              // độ dài CP-ABE ciphertext

    // Chuyển sang network byte order để nhất quán
    sym_len = htonl(sym_len);
    abe_len = htonl(abe_len);

    // Ghi header (8 byte)
    fwrite(&sym_len, sizeof(uint32_t), 1, out_fp);
    fwrite(&abe_len, sizeof(uint32_t), 1, out_fp);

    // Ghi phần ciphertext AES
    fwrite(encrypted_data, 1, ciphertext_len, out_fp);
    // Ghi CP-ABE ciphertext
    fwrite(cph_buf->data, 1, cph_buf->len, out_fp);

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
