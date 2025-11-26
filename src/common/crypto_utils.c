#include "crypto_utils.h"
#include "protocol.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <string.h>
#include <stdio.h>

#define PBKDF2_ITERATIONS 100000
#define MASTER_KEY_LEN 32

/* PBKDF2로 마스터키 유도 */
int derive_master_key(
    const char* password,
    const unsigned char* salt,
    size_t salt_len,
    unsigned char* key,
    size_t key_len
) {
    if (!password || !salt || !key) {
        return -1;
    }
    
    int ret = PKCS5_PBKDF2_HMAC(
        password,
        strlen(password),
        salt,
        salt_len,
        PBKDF2_ITERATIONS,
        EVP_sha256(),
        key_len,
        key
    );
    
    return ret == 1 ? 0 : -1;
}

/* Verifier 생성 (HMAC-SHA256) */
int create_verifier(
    const unsigned char* master_key,
    size_t key_len,
    const char* email,
    unsigned char* verifier,
    size_t verifier_len
) {
    if (!master_key || !email || !verifier || verifier_len < 32) {
        return -1;
    }
    
    unsigned int len = verifier_len;
    unsigned char* result = HMAC(
        EVP_sha256(),
        master_key,
        key_len,
        (unsigned char*)email,
        strlen(email),
        verifier,
        &len
    );
    
    return result ? 0 : -1;
}

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
) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    
    int len;
    int ciphertext_len;
    
    // 암호화 초기화
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    // AAD 설정 (선택적)
    if (aad && aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
    }
    
    // 평문 암호화
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;
    
    // 암호화 종료
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;
    
    // TAG 추출
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

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
) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    
    int len;
    int plaintext_len;
    
    // 복호화 초기화
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    // AAD 설정 (선택적)
    if (aad && aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
    }
    
    // 암호문 복호화
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;
    
    // TAG 설정 및 검증
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    // 복호화 종료 및 TAG 검증
    int ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    
    if (ret > 0) {
        plaintext_len += len;
        return plaintext_len;
    } else {
        return -1; // TAG 검증 실패
    }
}

/* 랜덤 바이트 생성 */
int generate_random_bytes(unsigned char* buf, size_t len) {
    return RAND_bytes(buf, len) == 1 ? 0 : -1;
}

/* 세션 토큰 생성 */
int generate_session_token(char* token, size_t token_len) {
    if (token_len < SESSION_TOKEN_LEN * 2 + 1) {
        return -1;
    }
    
    unsigned char random_bytes[SESSION_TOKEN_LEN];
    if (generate_random_bytes(random_bytes, SESSION_TOKEN_LEN) != 0) {
        return -1;
    }
    
    // Hex 인코딩
    for (size_t i = 0; i < SESSION_TOKEN_LEN; i++) {
        sprintf(token + (i * 2), "%02x", random_bytes[i]);
    }
    token[SESSION_TOKEN_LEN * 2] = '\0';
    
    return 0;
}

/* 메모리 안전 제거 */
void secure_zero(void* ptr, size_t len) {
    if (ptr) {
        OPENSSL_cleanse(ptr, len);
    }
}

