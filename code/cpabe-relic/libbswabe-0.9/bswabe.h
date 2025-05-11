/*
 * NOTE: You must include <glib.h> before including this file.
 *       This header uses GByteArray* in its API.
 */

 #ifndef BSWABE_H
 #define BSWABE_H
  
 #ifndef fp12_norm
 static inline void fp12_norm(fp12_t m) {
      fp12_conv_cyc(m, m);
 }
 #endif
 #define AES_KEY_LEN 16
 #define IV_SIZE 12
 #define TAG_SIZE 16
 
 // Fallback for gt_norm() if RELIC was built without full GT support
 #define gt_norm(m) fp12_norm(m)
 #define SAFE_GT_CAPACITY 1024 
 #define HEADER_SIZE (sizeof(uint32_t) * 2)

 #ifdef __cplusplus
 extern "C" {
 #endif
 
 typedef struct bswabe_pub_s bswabe_pub_t;
 typedef struct bswabe_msk_s bswabe_msk_t;
 typedef struct bswabe_prv_s bswabe_prv_t;
 typedef struct bswabe_cph_s bswabe_cph_t;
 
 /* API Functions */
 void bswabe_setup(bswabe_pub_t** pub, bswabe_msk_t** msk);
 bswabe_prv_t* bswabe_keygen(bswabe_pub_t* pub, bswabe_msk_t* msk, char** attributes);
 bswabe_cph_t* bswabe_enc(bswabe_pub_t* pub, gt_t m, char* policy);
 int bswabe_dec(bswabe_pub_t* pub, bswabe_prv_t* prv, bswabe_cph_t* cph, gt_t m);
 
 void bswabe_pub_free(bswabe_pub_t* pub);
 void bswabe_msk_free(bswabe_msk_t* msk);
 void bswabe_prv_free(bswabe_prv_t* prv);
 void bswabe_cph_free(bswabe_cph_t* cph);
 
 char* bswabe_error();
 
 /* Serialization */
 bswabe_pub_t* bswabe_pub_unserialize(GByteArray* buf, int free);
 GByteArray* bswabe_pub_serialize(bswabe_pub_t* pub);
 bswabe_msk_t* bswabe_msk_unserialize(bswabe_pub_t* pub, GByteArray* b, int free);
 GByteArray* bswabe_msk_serialize(bswabe_msk_t* msk);
 bswabe_prv_t* bswabe_prv_unserialize(bswabe_pub_t* pub, GByteArray* buf, int free);
 GByteArray* bswabe_prv_serialize(bswabe_prv_t* prv);
 bswabe_cph_t* bswabe_cph_unserialize(bswabe_pub_t* pub, GByteArray* buf, int free);
 GByteArray* bswabe_cph_serialize(bswabe_cph_t* cph);
 

 void debug_cph_cs(bswabe_cph_t* cph);
 void normalize_attr(char* dst, const char* src);
 int cmp_int(const void* a, const void* b);
 #ifdef __cplusplus
 }
 #endif
 
 #endif // BSWABE_H
 