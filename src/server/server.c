#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "../common/protocol.h"
#include "../common/tls_common.h"
#include "../common/crypto_utils.h"
#include "auth_manager.h"
#include "storage_manager.h"

#define PORT 4433
#define BACKLOG 10

/* JSON 파싱 헬퍼 (간단한 구현) */
static char* json_get_string(const char* json, const char* key) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\":\"", key);
    
    char* start = strstr(json, search);
    if (!start) return NULL;
    
    start += strlen(search);
    char* end = strchr(start, '"');
    if (!end) return NULL;
    
    size_t len = end - start;
    char* result = malloc(len + 1);
    memcpy(result, start, len);
    result[len] = '\0';
    
    return result;
}

static int json_get_int(const char* json, const char* key) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\":", key);
    
    char* start = strstr(json, search);
    if (!start) return -1;
    
    start += strlen(search);
    return atoi(start);
}

/* REGISTER 핸들러 */
static char* handle_register(const char* json) {
    char* email = json_get_string(json, "email");
    char* salt_b64 = json_get_string(json, "salt");
    char* verifier_b64 = json_get_string(json, "verifier");
    
    if (!email || !salt_b64 || !verifier_b64) {
        char* response = malloc(256);
        snprintf(response, 256, "{\"type\":\"RESPONSE\",\"status\":%d,\"message\":\"Missing fields\"}", STATUS_ERROR);
        free(email); free(salt_b64); free(verifier_b64);
        return response;
    }
    
    // Base64 디코딩
    size_t salt_len, verifier_len;
    unsigned char* salt = base64_decode(salt_b64, strlen(salt_b64), &salt_len);
    unsigned char* verifier = base64_decode(verifier_b64, strlen(verifier_b64), &verifier_len);
    
    // 사용자 등록
    int ret = auth_register_user(email, salt, salt_len, verifier, verifier_len);
    
    char* response = malloc(512);
    if (ret == 0) {
        snprintf(response, 512, "{\"type\":\"RESPONSE\",\"status\":%d,\"message\":\"Registration successful\"}", STATUS_OK);
    } else if (ret == -2) {
        snprintf(response, 512, "{\"type\":\"RESPONSE\",\"status\":%d,\"message\":\"User already exists\"}", STATUS_ALREADY_EXISTS);
    } else {
        snprintf(response, 512, "{\"type\":\"RESPONSE\",\"status\":%d,\"message\":\"Registration failed\"}", STATUS_ERROR);
    }
    
    free(email); free(salt_b64); free(verifier_b64);
    free(salt); free(verifier);
    
    return response;
}

/* GET_SALT 핸들러 */
static char* handle_get_salt(const char* json) {
    char* email = json_get_string(json, "email");
    
    if (!email) {
        char* response = malloc(256);
        snprintf(response, 256, "{\"type\":\"RESPONSE\",\"status\":%d,\"message\":\"Missing email\"}", STATUS_ERROR);
        return response;
    }
    
    // Salt 조회
    unsigned char salt[SALT_LEN];
    size_t salt_len;
    int ret = auth_get_salt(email, salt, &salt_len);
    
    if (ret != 0) {
        char* response = malloc(256);
        snprintf(response, 256, "{\"type\":\"RESPONSE\",\"status\":%d,\"message\":\"User not found\"}", STATUS_NOT_FOUND);
        free(email);
        return response;
    }
    
    // Base64 인코딩
    size_t salt_b64_len;
    char* salt_b64 = base64_encode(salt, salt_len, &salt_b64_len);
    
    // 응답 생성
    char* response = malloc(512);
    snprintf(response, 512, "{\"type\":\"RESPONSE\",\"status\":%d,\"salt\":\"%s\"}", STATUS_OK, salt_b64);
    
    free(email);
    free(salt_b64);
    
    return response;
}

/* LOGIN 핸들러 */
static char* handle_login(const char* json) {
    char* email = json_get_string(json, "email");
    char* verifier_b64 = json_get_string(json, "verifier");
    
    if (!email || !verifier_b64) {
        char* response = malloc(256);
        snprintf(response, 256, "{\"type\":\"RESPONSE\",\"status\":%d,\"message\":\"Missing fields\"}", STATUS_ERROR);
        free(email); free(verifier_b64);
        return response;
    }
    
    // Base64 디코딩
    size_t verifier_len;
    unsigned char* verifier = base64_decode(verifier_b64, strlen(verifier_b64), &verifier_len);
    
    // 로그인 시도
    char* token = auth_login_user(email, verifier, verifier_len);
    
    char* response = malloc(512);
    if (token) {
        snprintf(response, 512, "{\"type\":\"RESPONSE\",\"status\":%d,\"token\":\"%s\",\"message\":\"Login successful\"}", 
                STATUS_OK, token);
    } else {
        snprintf(response, 512, "{\"type\":\"RESPONSE\",\"status\":%d,\"message\":\"Authentication failed\"}", 
                STATUS_AUTH_FAILED);
    }
    
    free(email); free(verifier_b64); free(verifier);
    
    return response;
}

/* PUT 핸들러 */
static char* handle_put(const char* json) {
    char* token = json_get_string(json, "token");
    char* iv_b64 = json_get_string(json, "iv");
    char* tag_b64 = json_get_string(json, "tag");
    char* blob_b64 = json_get_string(json, "blob");
    char* meta = json_get_string(json, "meta");
    
    if (!token || !iv_b64 || !tag_b64 || !blob_b64) {
        char* response = malloc(256);
        snprintf(response, 256, "{\"type\":\"RESPONSE\",\"status\":%d,\"message\":\"Missing fields\"}", STATUS_ERROR);
        free(token); free(iv_b64); free(tag_b64); free(blob_b64); free(meta);
        return response;
    }
    
    // 토큰 검증
    char email[256];
    if (!auth_verify_token(token, email, sizeof(email))) {
        char* response = malloc(256);
        snprintf(response, 256, "{\"type\":\"RESPONSE\",\"status\":%d,\"message\":\"Invalid token\"}", 
                STATUS_INVALID_TOKEN);
        free(token); free(iv_b64); free(tag_b64); free(blob_b64); free(meta);
        return response;
    }
    
    // Base64 디코딩
    size_t iv_len, tag_len, blob_len;
    unsigned char* iv = base64_decode(iv_b64, strlen(iv_b64), &iv_len);
    unsigned char* tag = base64_decode(tag_b64, strlen(tag_b64), &tag_len);
    unsigned char* blob = base64_decode(blob_b64, strlen(blob_b64), &blob_len);
    
    // 아이템 저장
    int item_id = storage_put_item(email, iv, tag, blob, blob_len, meta);
    
    char* response = malloc(512);
    if (item_id > 0) {
        snprintf(response, 512, "{\"type\":\"RESPONSE\",\"status\":%d,\"item_id\":%d,\"message\":\"Item stored\"}", 
                STATUS_OK, item_id);
    } else {
        snprintf(response, 512, "{\"type\":\"RESPONSE\",\"status\":%d,\"message\":\"Storage failed\"}", STATUS_ERROR);
    }
    
    free(token); free(iv_b64); free(tag_b64); free(blob_b64); free(meta);
    free(iv); free(tag); free(blob);
    
    return response;
}

/* GET 핸들러 */
static char* handle_get(const char* json) {
    char* token = json_get_string(json, "token");
    int item_id = json_get_int(json, "item_id");
    
    if (!token || item_id < 0) {
        char* response = malloc(256);
        snprintf(response, 256, "{\"type\":\"RESPONSE\",\"status\":%d,\"message\":\"Missing fields\"}", STATUS_ERROR);
        free(token);
        return response;
    }
    
    // 토큰 검증
    char email[256];
    if (!auth_verify_token(token, email, sizeof(email))) {
        char* response = malloc(256);
        snprintf(response, 256, "{\"type\":\"RESPONSE\",\"status\":%d,\"message\":\"Invalid token\"}", 
                STATUS_INVALID_TOKEN);
        free(token);
        return response;
    }
    
    // 아이템 조회
    VaultItem* item = storage_get_item(item_id, email);
    
    if (!item) {
        char* response = malloc(256);
        snprintf(response, 256, "{\"type\":\"RESPONSE\",\"status\":%d,\"message\":\"Item not found\"}", 
                STATUS_NOT_FOUND);
        free(token);
        return response;
    }
    
    // Base64 인코딩
    size_t iv_b64_len, tag_b64_len, blob_b64_len;
    char* iv_b64 = base64_encode(item->iv, 12, &iv_b64_len);
    char* tag_b64 = base64_encode(item->tag, 16, &tag_b64_len);
    char* blob_b64 = base64_encode(item->blob, item->blob_len, &blob_b64_len);
    
    // 응답 생성 (평면 구조로 변경)
    char* response = malloc(blob_b64_len + 1024);
    snprintf(response, blob_b64_len + 1024, 
            "{\"type\":\"RESPONSE\",\"status\":%d,\"item_id\":%d,\"iv\":\"%s\",\"tag\":\"%s\",\"blob\":\"%s\",\"meta\":\"%s\"}", 
            STATUS_OK, item->id, iv_b64, tag_b64, blob_b64, item->meta);
    
    free(token);
    free(iv_b64); free(tag_b64); free(blob_b64);
    
    return response;
}

/* LIST 핸들러 */
static char* handle_list(const char* json) {
    char* token = json_get_string(json, "token");
    
    if (!token) {
        char* response = malloc(256);
        snprintf(response, 256, "{\"type\":\"RESPONSE\",\"status\":%d,\"message\":\"Missing fields\"}", STATUS_ERROR);
        return response;
    }
    
    // 토큰 검증
    char email[256];
    if (!auth_verify_token(token, email, sizeof(email))) {
        char* response = malloc(256);
        snprintf(response, 256, "{\"type\":\"RESPONSE\",\"status\":%d,\"message\":\"Invalid token\"}", 
                STATUS_INVALID_TOKEN);
        free(token);
        return response;
    }
    
    // 아이템 목록 조회
    int count;
    VaultItem** items = storage_list_items(email, &count);
    
    // 응답 생성 (간단히)
    char* response = malloc(64 * 1024); // 충분한 버퍼
    int offset = snprintf(response, 64 * 1024, "{\"type\":\"RESPONSE\",\"status\":%d,\"items\":[", STATUS_OK);
    
    for (int i = 0; i < count; i++) {
        if (i > 0) offset += snprintf(response + offset, 64 * 1024 - offset, ",");
        offset += snprintf(response + offset, 64 * 1024 - offset, 
                          "{\"id\":%d,\"meta\":\"%s\",\"created_at\":%ld}", 
                          items[i]->id, items[i]->meta, items[i]->created_at);
    }
    
    snprintf(response + offset, 64 * 1024 - offset, "]}");
    
    storage_free_item_list(items, count);
    free(token);
    
    return response;
}

/* 클라이언트 처리 */
static void handle_client(SSL* ssl) {
    // 클라이언트 연결이 유지되는 동안 여러 요청 처리
    while (1) {
        uint8_t* data = NULL;
        uint32_t len = 0;
        
        // 요청 수신
        int ret = recv_frame(ssl, &data, &len);
        if (ret < 0) {
            // 연결 종료 또는 오류
            break;
        }
        
        // NULL 종료 보장
        char* json = malloc(len + 1);
        memcpy(json, data, len);
        json[len] = '\0';
        free(data);
        
        printf("Received: %s\n", json);
        
        // 타입 파싱
        char* type = json_get_string(json, "type");
        char* response = NULL;
        
        if (type && strcmp(type, "REGISTER") == 0) {
            response = handle_register(json);
        } else if (type && strcmp(type, "GET_SALT") == 0) {
            response = handle_get_salt(json);
        } else if (type && strcmp(type, "LOGIN") == 0) {
            response = handle_login(json);
        } else if (type && strcmp(type, "PUT") == 0) {
            response = handle_put(json);
        } else if (type && strcmp(type, "GET") == 0) {
            response = handle_get(json);
        } else if (type && strcmp(type, "LIST") == 0) {
            response = handle_list(json);
        } else {
            response = malloc(256);
            snprintf(response, 256, "{\"type\":\"RESPONSE\",\"status\":%d,\"message\":\"Unknown command\"}", 
                    STATUS_ERROR);
        }
        
        // 응답 전송
        if (response) {
            printf("Sending: %s\n", response);
            if (send_frame(ssl, (uint8_t*)response, strlen(response)) < 0) {
                free(response);
                free(type);
                free(json);
                break;
            }
            free(response);
        }
        
        free(type);
        free(json);
    }
}

int main(int argc, char* argv[]) {
    printf("=== Secure Network Vault Server ===\n");
    
    // 초기화
    init_openssl();
    auth_manager_init();
    storage_manager_init();
    
    // SSL 컨텍스트 생성
    SSL_CTX* ctx = create_server_context();
    if (!ctx) {
        fprintf(stderr, "Failed to create SSL context\n");
        return 1;
    }
    
    // 인증서 로드
    if (load_server_certificates(ctx, "certs/server.crt", "certs/server.key") != 0) {
        fprintf(stderr, "Failed to load certificates\n");
        SSL_CTX_free(ctx);
        return 1;
    }
    
    // 소켓 생성
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        SSL_CTX_free(ctx);
        return 1;
    }
    
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(server_fd);
        SSL_CTX_free(ctx);
        return 1;
    }
    
    if (listen(server_fd, BACKLOG) < 0) {
        perror("listen");
        close(server_fd);
        SSL_CTX_free(ctx);
        return 1;
    }
    
    printf("Server listening on port %d\n", PORT);
    
    // 메인 루프
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }
        
        printf("Client connected: %s:%d\n", 
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        
        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);
        
        if (SSL_accept(ssl) <= 0) {
            print_ssl_error("SSL_accept failed");
        } else {
            printf("TLS handshake successful\n");
            handle_client(ssl);
        }
        
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
        
        printf("Client disconnected\n");
    }
    
    // 정리
    close(server_fd);
    SSL_CTX_free(ctx);
    
    auth_manager_cleanup();
    storage_manager_cleanup();
    cleanup_openssl();
    
    return 0;
}

