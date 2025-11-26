#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <stddef.h>

/* 메시지 타입 */
#define MSG_REGISTER    1
#define MSG_LOGIN       2
#define MSG_GET_SALT    3
#define MSG_PUT         4
#define MSG_GET         5
#define MSG_LIST        6
#define MSG_RESPONSE    100

/* 상태 코드 */
#define STATUS_OK                  0
#define STATUS_ERROR               1
#define STATUS_AUTH_FAILED         2
#define STATUS_INVALID_TOKEN       3
#define STATUS_NOT_FOUND           4
#define STATUS_ALREADY_EXISTS      5

/* 프로토콜 상수 */
#define MAX_MESSAGE_SIZE    (10 * 1024 * 1024)  // 10MB
#define MAX_EMAIL_LEN       256
#define MAX_TOKEN_LEN       64
#define SALT_LEN            32
#define VERIFIER_LEN        64
#define IV_LEN              12
#define TAG_LEN             16
#define SESSION_TOKEN_LEN   32

/* Base64 인코딩/디코딩 함수 */
char* base64_encode(const unsigned char* data, size_t len, size_t* out_len);
unsigned char* base64_decode(const char* data, size_t len, size_t* out_len);

/* 길이 prefix 프레이밍 함수 */
int send_frame(void* ssl, const uint8_t* data, uint32_t len);
int recv_frame(void* ssl, uint8_t** data, uint32_t* len);

/* JSON 유틸리티 함수 (간단한 구현) */
char* json_escape_string(const char* str);
void json_free(void* ptr);

#endif /* PROTOCOL_H */

