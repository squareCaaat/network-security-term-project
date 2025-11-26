#ifndef TLS_COMMON_H
#define TLS_COMMON_H

#include <openssl/ssl.h>
#include <openssl/err.h>

/* TLS 초기화 */
int init_openssl(void);
void cleanup_openssl(void);

/* SSL 컨텍스트 생성 - 서버용 */
SSL_CTX* create_server_context(void);

/* SSL 컨텍스트 생성 - 클라이언트용 */
SSL_CTX* create_client_context(void);

/* 서버 인증서/키 로드 */
int load_server_certificates(SSL_CTX* ctx, const char* cert_file, const char* key_file);

/* CA 인증서 로드 (클라이언트 검증용) */
int load_ca_certificate(SSL_CTX* ctx, const char* ca_file);

/* TLS 설정 강화 (TLS 1.3 강제 등) */
void configure_ssl_context(SSL_CTX* ctx);

/* 에러 출력 헬퍼 */
void print_ssl_error(const char* msg);

#endif /* TLS_COMMON_H */

