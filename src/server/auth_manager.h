#ifndef AUTH_MANAGER_H
#define AUTH_MANAGER_H

#include <stddef.h>
#include <stdbool.h>
#include <time.h>

/* 사용자 정보 구조체 */
typedef struct {
    char email[256];
    unsigned char salt[32];
    unsigned char verifier[64];
    char session_token[65];
    time_t session_created;
} User;

/* 인증 관리자 초기화 */
int auth_manager_init(void);

/* 인증 관리자 정리 */
void auth_manager_cleanup(void);

/* 사용자 등록 */
int auth_register_user(const char* email, const unsigned char* salt, 
                       size_t salt_len, const unsigned char* verifier, 
                       size_t verifier_len);

/* 사용자 로그인 (verifier 검증 및 세션 토큰 발급) */
char* auth_login_user(const char* email, const unsigned char* verifier, 
                     size_t verifier_len);

/* 세션 토큰 검증 */
bool auth_verify_token(const char* token, char* out_email, size_t email_len);

/* 사용자 존재 확인 */
bool auth_user_exists(const char* email);

/* Salt 조회 */
int auth_get_salt(const char* email, unsigned char* salt, size_t* salt_len);

#endif /* AUTH_MANAGER_H */

