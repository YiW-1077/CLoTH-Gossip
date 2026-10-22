#ifndef M3_HMAC_H
#define M3_HMAC_H

#include <stddef.h>
#include <stdint.h>

/* method3 のハッシュチェーン (CLOTH_M3_HASHCHAIN) 用の SHA-256 と HMAC-SHA256 (FIPS 180-4・RFC 2104)。
 * 外部のライブラリを使わない実装。m3_hmac_selftest() は FIPS 180 の "abc" と RFC 4231 の例 1・2 で確かめ、
 * 合っていれば 1 を返す。 */
void m3_sha256(const uint8_t* data, size_t len, uint8_t out[32]);
void m3_hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* data, size_t len, uint8_t out[32]);
int m3_hmac_selftest(void);

#endif
