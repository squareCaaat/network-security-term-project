#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <stdint.h>
#include <stddef.h>

/* KDF 함수 - PBKDF2 기반 */
int derive_master_key(
    const char* password,
    const unsigned char* salt,
    size_t salt_len,
    unsigned char* key,
    size_t key_len
);

/* Verifier 생성 (HMAC-SHA256 기반) */
int create_verifier(
    const unsigned char* master_key,
    size_t key_len,
    const char* email,
    unsigned char* verifier,
    size_t verifier_len
);

/* AES-256-GCM 암호화 */
int aes_gcm_encrypt(
    const unsigned char* plaintext,
    size_t plaintext_len,
    const unsigned char* key,
    const unsigned char* iv,
    const unsigned char* aad,
    size_t aad_len,
    unsigned char* ciphertext,
    unsigned char* tag
);

/* AES-256-GCM 복호화 */
int aes_gcm_decrypt(
    const unsigned char* ciphertext,
    size_t ciphertext_len,
    const unsigned char* key,
    const unsigned char* iv,
    const unsigned char* aad,
    size_t aad_len,
    const unsigned char* tag,
    unsigned char* plaintext
);

/* 랜덤 바이트 생성 */
int generate_random_bytes(unsigned char* buf, size_t len);

/* 세션 토큰 생성 */
int generate_session_token(char* token, size_t token_len);

/* 메모리 안전 제거 */
void secure_zero(void* ptr, size_t len);

#endif /* CRYPTO_UTILS_H */

