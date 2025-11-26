#include "auth_manager.h"
#include "../common/crypto_utils.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define MAX_USERS 1000
#define SESSION_TIMEOUT 3600  // 1시간

static User users[MAX_USERS];
static int user_count = 0;
static char users_db_file[] = "data/users.db";

/* 인증 관리자 초기화 */
int auth_manager_init(void) {
    FILE* fp = fopen(users_db_file, "rb");
    if (fp) {
        fread(&user_count, sizeof(int), 1, fp);
        fread(users, sizeof(User), user_count, fp);
        fclose(fp);
    }
    return 0;
}

/* 인증 관리자 정리 */
void auth_manager_cleanup(void) {
    FILE* fp = fopen(users_db_file, "wb");
    if (fp) {
        fwrite(&user_count, sizeof(int), 1, fp);
        fwrite(users, sizeof(User), user_count, fp);
        fclose(fp);
    }
}

/* 사용자 찾기 */
static User* find_user_by_email(const char* email) {
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].email, email) == 0) {
            return &users[i];
        }
    }
    return NULL;
}

/* 사용자 찾기 (토큰으로) */
static User* find_user_by_token(const char* token) {
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].session_token, token) == 0) {
            // 세션 타임아웃 체크
            time_t now = time(NULL);
            if (now - users[i].session_created < SESSION_TIMEOUT) {
                return &users[i];
            }
        }
    }
    return NULL;
}

/* 사용자 등록 */
int auth_register_user(const char* email, const unsigned char* salt, 
                       size_t salt_len, const unsigned char* verifier, 
                       size_t verifier_len) {
    if (user_count >= MAX_USERS) {
        return -1;
    }
    
    if (find_user_by_email(email)) {
        return -2; // 이미 존재
    }
    
    User* user = &users[user_count];
    memset(user, 0, sizeof(User));  // 전체 초기화
    strncpy(user->email, email, sizeof(user->email) - 1);
    memcpy(user->salt, salt, salt_len < 32 ? salt_len : 32);
    memcpy(user->verifier, verifier, verifier_len < 64 ? verifier_len : 64);
    user->session_token[0] = '\0';
    user->session_created = 0;
    
    user_count++;
    
    // 즉시 저장
    auth_manager_cleanup();
    
    return 0;
}

/* 사용자 로그인 */
char* auth_login_user(const char* email, const unsigned char* verifier, 
                     size_t verifier_len) {
    User* user = find_user_by_email(email);
    if (!user) {
        return NULL;
    }
    
    // Verifier 비교 (HMAC-SHA256 = 32바이트)
    size_t cmp_len = 32;  // HMAC-SHA256 고정 크기
    if (memcmp(user->verifier, verifier, cmp_len) != 0) {
        return NULL;
    }
    
    // 세션 토큰 생성
    if (generate_session_token(user->session_token, sizeof(user->session_token)) != 0) {
        return NULL;
    }
    user->session_created = time(NULL);
    
    // 즉시 저장
    auth_manager_cleanup();
    
    return user->session_token;
}

/* 세션 토큰 검증 */
bool auth_verify_token(const char* token, char* out_email, size_t email_len) {
    User* user = find_user_by_token(token);
    if (user) {
        if (out_email) {
            strncpy(out_email, user->email, email_len - 1);
            out_email[email_len - 1] = '\0';
        }
        return true;
    }
    return false;
}

/* 사용자 존재 확인 */
bool auth_user_exists(const char* email) {
    return find_user_by_email(email) != NULL;
}

/* Salt 조회 */
int auth_get_salt(const char* email, unsigned char* salt, size_t* salt_len) {
    User* user = find_user_by_email(email);
    if (!user) {
        return -1;
    }
    
    memcpy(salt, user->salt, 32);
    *salt_len = 32;
    return 0;
}

