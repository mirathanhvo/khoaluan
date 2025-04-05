#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <relic.h>
#include <relic_test.h>

// Include các header của bạn
#include "../libbswabe-0.9/bswabe.h"  // Khai báo bswabe_pub_t, bswabe_msk_t, bswabe_keygen...
#include "common.h"                  // parse_args, bswabe_error, v.v.
#include "private.h"                 // private.h nếu cần

// (Nếu bạn muốn in usage, bạn có thể giữ `usage` hoặc xóa nếu không cần)
char* usage =
"Usage: cpabe-keygen [OPTION ...] PUB_KEY MASTER_KEY ATTR [ATTR ...]\n"
"\n"
"Generate a key with the listed attributes using public key PUB_KEY and\n"
"master secret key MASTER_KEY. Output will be written to the file\n"
"\"priv_key\" unless the -o option is specified.\n"
"\n"
"Attributes come in two forms: non-numerical and numerical. Non-numerical\n"
"attributes are simply any string of letters, digits, and underscores\n"
"beginning with a letter.\n"
"\n"
"Numerical attributes are specified as `attr = N', where N is a non-negative\n"
"integer less than 2^64 and `attr' is another string. The whitespace around\n"
"the `=' is optional. One may specify an explicit length of k bits for the\n"
"integer by giving `attr = N#k'. Note that any comparisons in a policy given\n"
"to cpabe-enc(1) must then specify the same number of bits, e.g.,\n"
"`attr > 5#12'.\n"
"\n"
"The keywords `and', `or', and `of', are reserved for the policy language\n"
"of cpabe-enc (1) and may not be used for either type of attribute.\n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help               print this message\n\n"
" -v, --version            print version information\n\n"
" -o, --output FILE        write resulting key to FILE\n\n"
" -d, --deterministic      use deterministic \"random\" numbers\n"
"                          (only for debugging)\n\n"
"";

int main(int argc, char** argv) {
    // 1) Xử lý tham số dòng lệnh
    parse_args(argc, argv);

    // 2) Khởi tạo RELIC
    if (core_init() != RLC_OK) {
        core_clean();
        printf("Error initializing RELIC.\n");
        return 1;
    }
    if (pc_param_set_any() != RLC_OK) {
        printf("Error setting pairing parameters.\n");
        core_clean();
        return 1;
    }

    // 3) Đọc public key từ file pub_file
    FILE* pub_fp = fopen(pub_file, "rb");
    if (!pub_fp) {
        printf("Error opening public key file.\n");
        core_clean();
        return 1;
    }
    fseek(pub_fp, 0, SEEK_END);
    long pub_len = ftell(pub_fp);
    fseek(pub_fp, 0, SEEK_SET);
    uint8_t* pub_data = malloc(pub_len + 1024);  // Thêm dung lượng dự phòng
    if (!pub_data) {
        printf("Error: Memory allocation failed for public key data.\n");
        fclose(pub_fp);
        core_clean();
        return 1;
    }
    if (fread(pub_data, 1, pub_len, pub_fp) != pub_len) {
        printf("Error: Failed to read public key file.\n");
        free(pub_data);
        fclose(pub_fp);
        core_clean();
        return 1;
    }
    fclose(pub_fp);

    printf("Public key size: %ld\n", pub_len);  // In ra kích thước của public key

    GByteArray* pub_buf = g_byte_array_new_take(pub_data, pub_len);
    bswabe_pub_t* pub = bswabe_pub_unserialize(pub_buf, 1);
    if (!pub) {
        printf("Error unserializing public key.\n");
        g_byte_array_free(pub_buf, TRUE);
        core_clean();
        return 1;
    }

    // 4) Đọc master key từ file msk_file
    FILE* msk_fp = fopen(msk_file, "rb");
    if (!msk_fp) {
        printf("Error opening master secret key file.\n");
        bswabe_pub_free(pub);
        core_clean();
        return 1;
    }
    fseek(msk_fp, 0, SEEK_END);
    long msk_len = ftell(msk_fp);
    fseek(msk_fp, 0, SEEK_SET);
    uint8_t* msk_data = malloc(msk_len + 1024);  // Thêm dung lượng dự phòng
    if (!msk_data) {
        printf("Error: Memory allocation failed for master key data.\n");
        fclose(msk_fp);
        bswabe_pub_free(pub);
        core_clean();
        return 1;
    }
    if (fread(msk_data, 1, msk_len, msk_fp) != msk_len) {
        printf("Error: Failed to read master key file.\n");
        free(msk_data);
        fclose(msk_fp);
        bswabe_pub_free(pub);
        core_clean();
        return 1;
    }
    fclose(msk_fp);

    printf("Master key size: %ld\n", msk_len);  // In ra kích thước của master key

    // Dùng hàm bswabe_msk_unserialize để đọc master key
    GByteArray* msk_buf = g_byte_array_new_take(msk_data, msk_len);
    bswabe_msk_t* msk = bswabe_msk_unserialize(pub, msk_buf, 1);
    if (!msk) {
        fprintf(stderr, "ERROR: Failed to unserialize master key.\n");
        bswabe_pub_free(pub);
        core_clean();
        return 1;
    }

    // 5) Gọi hàm bswabe_keygen (định nghĩa trong core.c, prototype trong bswabe.h)
    //    => trả về bswabe_prv_t*
    bswabe_prv_t* prv = bswabe_keygen(pub, msk, attrs);
    if (!prv) {
        fprintf(stderr, "ERROR: bswabe_keygen() failed. Attributes might be invalid or master key corrupted.\n");
        bswabe_msk_free(msk);
        bswabe_pub_free(pub);
        core_clean();
        return 1;
    }

    // In ra các thuộc tính của private key
    printf("Generated Private Key attributes:\n");
    for (int i = 0; i < prv->comps_len; i++) {
        bswabe_prv_comp_t *comp = &g_array_index(prv->comps, bswabe_prv_comp_t, i);
        printf("  Attribute %d: %s\n", i, comp->attr ? comp->attr : "(null)");
    }

    // 6) Serialize private key
    GByteArray* prv_buf = bswabe_prv_serialize(prv);

    // 7) Ghi ra file out_file
    FILE* out_fp = fopen(out_file, "wb");
    if (!out_fp) {
        printf("Error opening private key output file.\n");
        g_byte_array_free(prv_buf, TRUE);
        bswabe_prv_free(prv);
        bswabe_msk_free(msk);
        bswabe_pub_free(pub);
        core_clean();
        return 1;
    }
    fwrite(prv_buf->data, 1, prv_buf->len, out_fp);
    fclose(out_fp);

    // 8) Giải phóng bộ nhớ
    g_byte_array_free(prv_buf, TRUE);
    bswabe_prv_free(prv);
    bswabe_msk_free(msk);
    bswabe_pub_free(pub);

    // 9) Kết thúc
    core_clean();
    return 0;
}