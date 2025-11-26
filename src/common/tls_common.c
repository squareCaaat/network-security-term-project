#include "tls_common.h"
#include <stdio.h>
#include <string.h>

/* OpenSSL 초기화 */
int init_openssl(void) {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    return 0;
}

/* OpenSSL 정리 */
void cleanup_openssl(void) {
    EVP_cleanup();
}

/* SSL 에러 출력 */
void print_ssl_error(const char* msg) {
    fprintf(stderr, "SSL Error: %s\n", msg);
    ERR_print_errors_fp(stderr);
}

/* TLS 컨텍스트 설정 강화 */
void configure_ssl_context(SSL_CTX* ctx) {
    // TLS 1.3 강제
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    
    // 보안 옵션 설정
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | 
                             SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | 
                             SSL_OP_NO_TLSv1_2);
    
    // 세션 캐시 비활성화 (보안 강화)
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
}

/* 서버 컨텍스트 생성 */
SSL_CTX* create_server_context(void) {
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    
    if (!ctx) {
        print_ssl_error("Unable to create SSL context");
        return NULL;
    }
    
    configure_ssl_context(ctx);
    return ctx;
}

/* 클라이언트 컨텍스트 생성 */
SSL_CTX* create_client_context(void) {
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    
    if (!ctx) {
        print_ssl_error("Unable to create SSL context");
        return NULL;
    }
    
    configure_ssl_context(ctx);
    
    // 서버 인증서 검증 활성화
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    
    return ctx;
}

/* 서버 인증서/키 로드 */
int load_server_certificates(SSL_CTX* ctx, const char* cert_file, const char* key_file) {
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        print_ssl_error("Failed to load certificate");
        return -1;
    }
    
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        print_ssl_error("Failed to load private key");
        return -1;
    }
    
    // 개인키와 인증서 일치 확인
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match certificate\n");
        return -1;
    }
    
    return 0;
}

/* CA 인증서 로드 */
int load_ca_certificate(SSL_CTX* ctx, const char* ca_file) {
    if (SSL_CTX_load_verify_locations(ctx, ca_file, NULL) <= 0) {
        print_ssl_error("Failed to load CA certificate");
        return -1;
    }
    return 0;
}

