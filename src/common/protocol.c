#include "protocol.h"
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

/* Base64 인코딩 */
char* base64_encode(const unsigned char* data, size_t len, size_t* out_len) {
    BIO *bio, *b64;
    BUF_MEM *buffer_ptr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data, len);
    BIO_flush(bio);
    
    BIO_get_mem_ptr(bio, &buffer_ptr);
    
    char* result = malloc(buffer_ptr->length + 1);
    memcpy(result, buffer_ptr->data, buffer_ptr->length);
    result[buffer_ptr->length] = '\0';
    
    if (out_len) *out_len = buffer_ptr->length;
    
    BIO_free_all(bio);
    return result;
}

/* Base64 디코딩 */
unsigned char* base64_decode(const char* data, size_t len, size_t* out_len) {
    BIO *bio, *b64;
    
    unsigned char* buffer = malloc(len);
    memset(buffer, 0, len);
    
    bio = BIO_new_mem_buf(data, len);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    *out_len = BIO_read(bio, buffer, len);
    
    BIO_free_all(bio);
    return buffer;
}

/* 길이 prefix 프레임 전송 */
int send_frame(void* ssl_ptr, const uint8_t* data, uint32_t len) {
    SSL* ssl = (SSL*)ssl_ptr;
    
    if (len > MAX_MESSAGE_SIZE) {
        return -1;
    }
    
    // 네트워크 바이트 오더로 길이 전송
    uint32_t net_len = htonl(len);
    int ret = SSL_write(ssl, &net_len, sizeof(net_len));
    if (ret != sizeof(net_len)) {
        return -1;
    }
    
    // 데이터 전송
    int total = 0;
    while (total < len) {
        ret = SSL_write(ssl, data + total, len - total);
        if (ret <= 0) {
            return -1;
        }
        total += ret;
    }
    
    return total;
}

/* 길이 prefix 프레임 수신 */
int recv_frame(void* ssl_ptr, uint8_t** data, uint32_t* len) {
    SSL* ssl = (SSL*)ssl_ptr;
    
    // 길이 수신
    uint32_t net_len;
    int ret = SSL_read(ssl, &net_len, sizeof(net_len));
    if (ret != sizeof(net_len)) {
        return -1;
    }
    
    *len = ntohl(net_len);
    
    // 최대 크기 체크
    if (*len > MAX_MESSAGE_SIZE) {
        return -1;
    }
    
    // 데이터 수신
    *data = malloc(*len);
    if (!*data) {
        return -1;
    }
    
    int total = 0;
    while (total < *len) {
        ret = SSL_read(ssl, *data + total, *len - total);
        if (ret <= 0) {
            free(*data);
            *data = NULL;
            return -1;
        }
        total += ret;
    }
    
    return total;
}

/* JSON 문자열 이스케이프 (간단한 구현) */
char* json_escape_string(const char* str) {
    if (!str) return NULL;
    
    size_t len = strlen(str);
    char* result = malloc(len * 2 + 1); // 최악의 경우 2배
    if (!result) return NULL;
    
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        if (str[i] == '"' || str[i] == '\\') {
            result[j++] = '\\';
        }
        result[j++] = str[i];
    }
    result[j] = '\0';
    
    return result;
}

/* JSON 메모리 해제 */
void json_free(void* ptr) {
    free(ptr);
}

