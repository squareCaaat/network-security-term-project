#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "../common/protocol.h"
#include "../common/tls_common.h"
#include "../common/crypto_utils.h"

#define SERVER_HOST "127.0.0.1"
#define SERVER_PORT 4433
#define MASTER_KEY_LEN 32

/* 전역 변수 */
static unsigned char master_key[MASTER_KEY_LEN];
static char session_token[128] = {0};
static char user_email[256] = {0};
static SSL* ssl = NULL;

/* TCP 연결 */
static int connect_to_server(const char* host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &addr.sin_addr);
    
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        return -1;
    }
    
    return fd;
}

/* JSON 파싱 헬퍼 */
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

/* 문자열 헬퍼 */
static char* duplicate_range(const char* start, size_t len) {
    char* buf = malloc(len + 1);
    if (!buf) return NULL;
    memcpy(buf, start, len);
    buf[len] = '\0';
    return buf;
}

static char* duplicate_cstring(const char* str) {
    if (!str) return NULL;
    return duplicate_range(str, strlen(str));
}

static void rtrim(char* str) {
    if (!str) return;
    size_t len = strlen(str);
    while (len > 0 && (str[len - 1] == ' ' || str[len - 1] == '\t')) {
        str[len - 1] = '\0';
        len--;
    }
}

static char* parse_quoted_argument(char** cursor) {
    if (!cursor || !*cursor) return NULL;
    char* ptr = *cursor;
    while (*ptr == ' ') ptr++;
    if (*ptr == '\0') {
        *cursor = ptr;
        return NULL;
    }

    char* result = NULL;
    if (*ptr == '\"') {
        ptr++;
        char* end = strchr(ptr, '\"');
        if (end) {
            result = duplicate_range(ptr, (size_t)(end - ptr));
            ptr = end + 1;
        } else {
            result = duplicate_cstring(ptr);
            ptr += strlen(ptr);
        }
    } else {
        char* end = ptr;
        while (*end && *end != ' ') end++;
        result = duplicate_range(ptr, (size_t)(end - ptr));
        ptr = end;
    }

    while (*ptr == ' ') ptr++;
    *cursor = ptr;
    return result;
}

static char* prompt_hidden_input(const char* prompt) {
    int is_tty = isatty(STDIN_FILENO);
    struct termios oldt;
    if (is_tty) {
        if (tcgetattr(STDIN_FILENO, &oldt) != 0) {
            if (errno != ENOTTY) {
                perror("tcgetattr");
            }
            is_tty = 0;
        }
    }

    if (is_tty) {
        struct termios newt = oldt;
        newt.c_lflag &= ~(ECHO);
        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &newt) != 0) {
            if (errno != ENOTTY) {
                perror("tcsetattr");
            }
            is_tty = 0;
        }
    }

    printf("%s", prompt);
    fflush(stdout);

    char* line = NULL;
    size_t len = 0;
    ssize_t read = getline(&line, &len, stdin);

    if (is_tty) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldt);
        printf("\n");
    } else {
        printf("\n");
    }

    if (read <= 0) {
        free(line);
        return NULL;
    }

    if (line[read - 1] == '\n') {
        line[read - 1] = '\0';
    }

    return line;
}

/* 요청 전송 및 응답 수신 */
static char* send_request(const char* request) {
    if (!ssl) {
        fprintf(stderr, "Not connected to server\n");
        return NULL;
    }
    
    // 요청 전송
    if (send_frame(ssl, (uint8_t*)request, strlen(request)) < 0) {
        fprintf(stderr, "Failed to send request\n");
        return NULL;
    }
    
    // 응답 수신
    uint8_t* data = NULL;
    uint32_t len = 0;
    if (recv_frame(ssl, &data, &len) < 0) {
        fprintf(stderr, "Failed to receive response\n");
        return NULL;
    }
    
    char* response = malloc(len + 1);
    memcpy(response, data, len);
    response[len] = '\0';
    free(data);
    
    return response;
}

/* 회원가입 */
static void cmd_register(const char* email, const char* password) {
    // Salt 생성
    unsigned char salt[SALT_LEN];
    generate_random_bytes(salt, SALT_LEN);
    
    // 마스터키 유도
    derive_master_key(password, salt, SALT_LEN, master_key, MASTER_KEY_LEN);
    
    // Verifier 생성 (HMAC-SHA256 = 32바이트)
    unsigned char verifier[32];  // HMAC-SHA256 출력 크기
    create_verifier(master_key, MASTER_KEY_LEN, email, verifier, 32);
    
    // Base64 인코딩
    size_t salt_b64_len, verifier_b64_len;
    char* salt_b64 = base64_encode(salt, SALT_LEN, &salt_b64_len);
    char* verifier_b64 = base64_encode(verifier, 32, &verifier_b64_len);  // 32바이트만 인코딩
    
    // JSON 요청 생성
    char request[4096];
    snprintf(request, sizeof(request),
            "{\"type\":\"REGISTER\",\"email\":\"%s\",\"salt\":\"%s\",\"verifier\":\"%s\"}",
            email, salt_b64, verifier_b64);
    
    // 요청 전송
    char* response = send_request(request);
    if (response) {
        int status = json_get_int(response, "status");
        char* message = json_get_string(response, "message");
        
        if (status == STATUS_OK) {
            printf("✓ Registration successful\n");
            strncpy(user_email, email, sizeof(user_email) - 1);
        } else {
            printf("✗ Registration failed: %s\n", message ? message : "Unknown error");
        }
        
        free(message);
        free(response);
    }
    
    free(salt_b64);
    free(verifier_b64);
    
    // 민감 데이터 제거
    secure_zero(verifier, 32);
}

/* 로그인 */
static void cmd_login(const char* email, const char* password) {
    // 1단계: 서버에서 salt 조회
    char get_salt_request[512];
    snprintf(get_salt_request, sizeof(get_salt_request),
            "{\"type\":\"GET_SALT\",\"email\":\"%s\"}",
            email);
    
    char* salt_response = send_request(get_salt_request);
    if (!salt_response) {
        printf("✗ Failed to retrieve salt\n");
        return;
    }
    
    int status = json_get_int(salt_response, "status");
    char* salt_b64 = json_get_string(salt_response, "salt");
    
    if (status != STATUS_OK || !salt_b64) {
        char* message = json_get_string(salt_response, "message");
        printf("✗ Failed to get salt: %s\n", message ? message : "User not found");
        free(message);
        free(salt_b64);
        free(salt_response);
        return;
    }
    
    // Salt 디코딩
    size_t salt_len;
    unsigned char* salt = base64_decode(salt_b64, strlen(salt_b64), &salt_len);
    free(salt_b64);
    free(salt_response);
    
    // 2단계: 마스터키 유도
    derive_master_key(password, salt, salt_len, master_key, MASTER_KEY_LEN);
    
    // Salt 제거
    secure_zero(salt, salt_len);
    free(salt);
    
    // Verifier 생성
    unsigned char verifier[VERIFIER_LEN];
    create_verifier(master_key, MASTER_KEY_LEN, email, verifier, VERIFIER_LEN);
    
    // Base64 인코딩
    size_t verifier_b64_len;
    char* verifier_b64 = base64_encode(verifier, 32, &verifier_b64_len);  // 32바이트만 인코딩
    
    // JSON 요청 생성
    char request[2048];
    snprintf(request, sizeof(request),
            "{\"type\":\"LOGIN\",\"email\":\"%s\",\"verifier\":\"%s\"}",
            email, verifier_b64);
    
    // 요청 전송
    char* response = send_request(request);
    if (response) {
        int status = json_get_int(response, "status");
        char* token = json_get_string(response, "token");
        char* message = json_get_string(response, "message");
        
        if (status == STATUS_OK && token) {
            printf("✓ Login successful\n");
            strncpy(session_token, token, sizeof(session_token) - 1);
            strncpy(user_email, email, sizeof(user_email) - 1);
        } else {
            printf("✗ Login failed: %s\n", message ? message : "Unknown error");
        }
        
        free(token);
        free(message);
        free(response);
    }
    
    free(verifier_b64);
    secure_zero(verifier, VERIFIER_LEN);
}

/* 데이터 저장 */
static void cmd_put(const char* plaintext, const char* meta) {
    if (session_token[0] == '\0') {
        printf("✗ Please login first\n");
        return;
    }
    
    // IV 생성
    unsigned char iv[IV_LEN];
    generate_random_bytes(iv, IV_LEN);
    
    // 암호화
    size_t plaintext_len = strlen(plaintext);
    unsigned char* ciphertext = malloc(plaintext_len + 16);
    unsigned char tag[TAG_LEN];
    
    int ciphertext_len = aes_gcm_encrypt(
        (unsigned char*)plaintext, plaintext_len,
        master_key, iv, NULL, 0,
        ciphertext, tag
    );
    
    if (ciphertext_len < 0) {
        printf("✗ Encryption failed\n");
        free(ciphertext);
        return;
    }
    
    // Base64 인코딩
    size_t iv_b64_len, tag_b64_len, blob_b64_len;
    char* iv_b64 = base64_encode(iv, IV_LEN, &iv_b64_len);
    char* tag_b64 = base64_encode(tag, TAG_LEN, &tag_b64_len);
    char* blob_b64 = base64_encode(ciphertext, ciphertext_len, &blob_b64_len);
    
    // JSON 요청 생성
    char* request = malloc(blob_b64_len + 2048);
    snprintf(request, blob_b64_len + 2048,
            "{\"type\":\"PUT\",\"token\":\"%s\",\"iv\":\"%s\",\"tag\":\"%s\",\"blob\":\"%s\",\"meta\":\"%s\"}",
            session_token, iv_b64, tag_b64, blob_b64, meta ? meta : "");
    
    // 요청 전송
    char* response = send_request(request);
    if (response) {
        int status = json_get_int(response, "status");
        int item_id = json_get_int(response, "item_id");
        
        if (status == STATUS_OK) {
            printf("✓ Item stored with ID: %d\n", item_id);
        } else {
            char* message = json_get_string(response, "message");
            printf("✗ Storage failed: %s\n", message ? message : "Unknown error");
            free(message);
        }
        
        free(response);
    }
    
    free(request);
    free(iv_b64);
    free(tag_b64);
    free(blob_b64);
    free(ciphertext);
    secure_zero(iv, IV_LEN);
    secure_zero(tag, TAG_LEN);
}

static void cmd_update(int item_id, const char* plaintext, const char* meta) {
    if (session_token[0] == '\0') {
        printf("✗ Please login first\n");
        return;
    }
    if (item_id <= 0) {
        printf("✗ Invalid item id\n");
        return;
    }
    
    unsigned char iv[IV_LEN];
    generate_random_bytes(iv, IV_LEN);
    
    size_t plaintext_len = strlen(plaintext);
    unsigned char* ciphertext = malloc(plaintext_len + 16);
    unsigned char tag[TAG_LEN];
    
    int ciphertext_len = aes_gcm_encrypt(
        (unsigned char*)plaintext, plaintext_len,
        master_key, iv, NULL, 0,
        ciphertext, tag
    );
    
    if (ciphertext_len < 0) {
        printf("✗ Encryption failed\n");
        free(ciphertext);
        return;
    }
    
    size_t iv_b64_len, tag_b64_len, blob_b64_len;
    char* iv_b64 = base64_encode(iv, IV_LEN, &iv_b64_len);
    char* tag_b64 = base64_encode(tag, TAG_LEN, &tag_b64_len);
    char* blob_b64 = base64_encode(ciphertext, ciphertext_len, &blob_b64_len);
    
    char* request = malloc(blob_b64_len + 2048);
    snprintf(request, blob_b64_len + 2048,
            "{\"type\":\"UPDATE\",\"token\":\"%s\",\"item_id\":%d,\"iv\":\"%s\",\"tag\":\"%s\",\"blob\":\"%s\",\"meta\":\"%s\"}",
            session_token, item_id, iv_b64, tag_b64, blob_b64, meta ? meta : "");
    
    char* response = send_request(request);
    if (response) {
        int status = json_get_int(response, "status");
        if (status == STATUS_OK) {
            printf("✓ Item %d updated\n", item_id);
        } else {
            char* message = json_get_string(response, "message");
            printf("✗ Update failed: %s\n", message ? message : "Unknown error");
            free(message);
        }
        free(response);
    }
    
    free(request);
    free(iv_b64);
    free(tag_b64);
    free(blob_b64);
    free(ciphertext);
    secure_zero(iv, IV_LEN);
    secure_zero(tag, TAG_LEN);
}

static void cmd_delete(int item_id) {
    if (session_token[0] == '\0') {
        printf("✗ Please login first\n");
        return;
    }
    if (item_id <= 0) {
        printf("✗ Invalid item id\n");
        return;
    }
    
    char request[512];
    snprintf(request, sizeof(request),
             "{\"type\":\"DELETE\",\"token\":\"%s\",\"item_id\":%d}",
             session_token, item_id);
    
    char* response = send_request(request);
    if (response) {
        int status = json_get_int(response, "status");
        if (status == STATUS_OK) {
            printf("✓ Item %d deleted\n", item_id);
        } else {
            char* message = json_get_string(response, "message");
            printf("✗ Delete failed: %s\n", message ? message : "Unknown error");
            free(message);
        }
        free(response);
    }
}
/* 데이터 조회 */
static void cmd_get(int item_id) {
    if (session_token[0] == '\0') {
        printf("✗ Please login first\n");
        return;
    }
    
    // JSON 요청 생성
    char request[512];
    snprintf(request, sizeof(request),
            "{\"type\":\"GET\",\"token\":\"%s\",\"item_id\":%d}",
            session_token, item_id);
    
    // 요청 전송
    char* response = send_request(request);
    if (response) {
        int status = json_get_int(response, "status");
        
        if (status == STATUS_OK) {
            // 아이템 데이터 추출
            char* iv_b64 = json_get_string(response, "iv");
            char* tag_b64 = json_get_string(response, "tag");
            char* blob_b64 = json_get_string(response, "blob");
            char* meta = json_get_string(response, "meta");
            
            if (iv_b64 && tag_b64 && blob_b64) {
                // Base64 디코딩
                size_t iv_len, tag_len, blob_len;
                unsigned char* iv = base64_decode(iv_b64, strlen(iv_b64), &iv_len);
                unsigned char* tag = base64_decode(tag_b64, strlen(tag_b64), &tag_len);
                unsigned char* blob = base64_decode(blob_b64, strlen(blob_b64), &blob_len);
                
                // 복호화
                unsigned char* plaintext = malloc(blob_len + 16);
                int plaintext_len = aes_gcm_decrypt(
                    blob, blob_len,
                    master_key, iv, NULL, 0,
                    tag, plaintext
                );
                
                if (plaintext_len >= 0) {
                    plaintext[plaintext_len] = '\0';
                    printf("\n=== Item %d ===\n", item_id);
                    printf("Meta: %s\n", meta ? meta : "(none)");
                    printf("Content: %s\n", plaintext);
                    printf("===============\n\n");
                } else {
                    printf("✗ Decryption failed (TAG verification failed)\n");
                }
                
                free(plaintext);
                free(iv);
                free(tag);
                free(blob);
            }
            
            free(iv_b64);
            free(tag_b64);
            free(blob_b64);
            free(meta);
        } else {
            char* message = json_get_string(response, "message");
            printf("✗ Get failed: %s\n", message ? message : "Unknown error");
            free(message);
        }
        
        free(response);
    }
}

/* 목록 조회 */
static void cmd_list(void) {
    if (session_token[0] == '\0') {
        printf("✗ Please login first\n");
        return;
    }
    
    // JSON 요청 생성
    char request[512];
    snprintf(request, sizeof(request),
            "{\"type\":\"LIST\",\"token\":\"%s\"}",
            session_token);
    
    // 요청 전송
    char* response = send_request(request);
    if (response) {
        int status = json_get_int(response, "status");
        
        if (status == STATUS_OK) {
            printf("\n=== Vault Items ===\n");
            
            // 간단한 파싱 (items 배열)
            char* items_start = strstr(response, "\"items\":[");
            if (items_start) {
                printf("%s\n", items_start);
            }
            
            printf("===================\n\n");
        } else {
            char* message = json_get_string(response, "message");
            printf("✗ List failed: %s\n", message ? message : "Unknown error");
            free(message);
        }
        
        free(response);
    }
}

/* 메인 함수 */
int main(int argc, char* argv[]) {
    printf("=== Secure Network Vault Client ===\n\n");
    
    // OpenSSL 초기화
    init_openssl();
    
    // SSL 컨텍스트 생성
    SSL_CTX* ctx = create_client_context();
    if (!ctx) {
        fprintf(stderr, "Failed to create SSL context\n");
        return 1;
    }
    
    // CA 인증서 로드 (자체 서명 인증서를 사용하는 경우)
    // load_ca_certificate(ctx, "certs/ca.crt");
    
    // 서버 인증서 검증 비활성화 (개발 목적)
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    
    // 서버 연결
    int fd = connect_to_server(SERVER_HOST, SERVER_PORT);
    if (fd < 0) {
        fprintf(stderr, "Failed to connect to server\n");
        SSL_CTX_free(ctx);
        return 1;
    }
    
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    
    if (SSL_connect(ssl) <= 0) {
        print_ssl_error("SSL_connect failed");
        SSL_free(ssl);
        close(fd);
        SSL_CTX_free(ctx);
        return 1;
    }
    
    printf("✓ Connected to server (TLS 1.3)\n\n");
    
    // 간단한 CLI
    printf("Commands:\n");
    printf("  register <email>\n");
    printf("  login <email>\n");
    printf("  put <meta> <text>  (meta/text may be wrapped in quotes)\n");
    printf("  update <id> <meta> <text>\n");
    printf("  delete <id>\n");
    printf("  get <id>\n");
    printf("  list\n");
    printf("  quit\n\n");
    
    while (1) {
        char* line = readline("> ");
        if (!line) {
            printf("\n");
            break;
        }
        
        if (strlen(line) == 0) {
            free(line);
            continue;
        }
        
        add_history(line);
        
        // 명령어 추출
        char* ptr = line;
        while (*ptr == ' ') ptr++; // 앞쪽 공백 제거
        
        char* cmd_end = strchr(ptr, ' ');
        char cmd[64] = {0};
        
        if (cmd_end) {
            size_t cmd_len = cmd_end - ptr;
            if (cmd_len >= sizeof(cmd)) cmd_len = sizeof(cmd) - 1;
            strncpy(cmd, ptr, cmd_len);
            ptr = cmd_end + 1;
            while (*ptr == ' ') ptr++; // 공백 제거
        } else {
            strncpy(cmd, ptr, sizeof(cmd) - 1);
            ptr += strlen(ptr);
        }
        
        // 명령 처리
        if (strcmp(cmd, "quit") == 0 || strcmp(cmd, "exit") == 0) {
            free(line);
            break;
        } else if (strcmp(cmd, "register") == 0) {
            char* parse_cursor = ptr;
            char* email = parse_quoted_argument(&parse_cursor);
            if (!email || strlen(email) == 0) {
                printf("Usage: register <email>\n");
                free(email);
                free(line);
                continue;
            }
            
            char* password = prompt_hidden_input("Password: ");
            if (!password || strlen(password) == 0) {
                printf("Password cannot be empty\n");
                if (password) {
                    secure_zero(password, strlen(password));
                    free(password);
                }
                free(email);
                free(line);
                continue;
            }
            
            cmd_register(email, password);
            secure_zero(password, strlen(password));
            free(password);
            free(email);
        } else if (strcmp(cmd, "login") == 0) {
            char* parse_cursor = ptr;
            char* email = parse_quoted_argument(&parse_cursor);
            if (!email || strlen(email) == 0) {
                printf("Usage: login <email>\n");
                free(email);
                free(line);
                continue;
            }
            
            char* password = prompt_hidden_input("Password: ");
            if (!password || strlen(password) == 0) {
                printf("Password cannot be empty\n");
                if (password) {
                    secure_zero(password, strlen(password));
                    free(password);
                }
                free(email);
                free(line);
                continue;
            }
            
            cmd_login(email, password);
            secure_zero(password, strlen(password));
            free(password);
            free(email);
        } else if (strcmp(cmd, "put") == 0) {
            if (strlen(ptr) == 0) {
                printf("Usage: put <meta> <text>\n");
                free(line);
                continue;
            }

            char* parse_cursor = ptr;
            char* meta = parse_quoted_argument(&parse_cursor);
            if (!meta || strlen(meta) == 0) {
                printf("Usage: put <meta> <text>\n");
                free(meta);
                free(line);
                continue;
            }

            char* text = NULL;
            if (*parse_cursor == '\0') {
                printf("Usage: put <meta> <text>\n");
                free(meta);
                free(line);
                continue;
            } else if (*parse_cursor == '\"') {
                text = parse_quoted_argument(&parse_cursor);
            } else {
                text = duplicate_cstring(parse_cursor);
                rtrim(text);
            }

            if (!text || strlen(text) == 0) {
                printf("Usage: put <meta> <text>\n");
                free(meta);
                free(text);
                free(line);
                continue;
            }

            cmd_put(text, meta);
            free(meta);
            free(text);
        } else if (strcmp(cmd, "update") == 0) {
            if (strlen(ptr) == 0) {
                printf("Usage: update <id> <meta> <text>\n");
                free(line);
                continue;
            }
            
            char* parse_cursor = ptr;
            char* id_str = parse_quoted_argument(&parse_cursor);
            if (!id_str || strlen(id_str) == 0) {
                printf("Usage: update <id> <meta> <text>\n");
                free(id_str);
                free(line);
                continue;
            }
            int item_id = atoi(id_str);
            free(id_str);
            if (item_id <= 0) {
                printf("✗ Invalid item id\n");
                free(line);
                continue;
            }
            
            char* meta = parse_quoted_argument(&parse_cursor);
            if (!meta || strlen(meta) == 0) {
                printf("Usage: update <id> <meta> <text>\n");
                free(meta);
                free(line);
                continue;
            }
            
            char* text = NULL;
            if (*parse_cursor == '\0') {
                printf("Usage: update <id> <meta> <text>\n");
                free(meta);
                free(line);
                continue;
            } else if (*parse_cursor == '\"') {
                text = parse_quoted_argument(&parse_cursor);
            } else {
                text = duplicate_cstring(parse_cursor);
                rtrim(text);
            }
            
            if (!text || strlen(text) == 0) {
                printf("Usage: update <id> <meta> <text>\n");
                free(meta);
                free(text);
                free(line);
                continue;
            }
            
            cmd_update(item_id, text, meta);
            free(meta);
            free(text);
        } else if (strcmp(cmd, "delete") == 0) {
            if (strlen(ptr) == 0) {
                printf("Usage: delete <id>\n");
                free(line);
                continue;
            }
            
            char* parse_cursor = ptr;
            char* id_str = parse_quoted_argument(&parse_cursor);
            if (!id_str || strlen(id_str) == 0) {
                printf("Usage: delete <id>\n");
                free(id_str);
                free(line);
                continue;
            }
            int item_id = atoi(id_str);
            free(id_str);
            
            if (item_id <= 0) {
                printf("✗ Invalid item id\n");
                free(line);
                continue;
            }
            
            cmd_delete(item_id);
        } else if (strcmp(cmd, "get") == 0) {
            // get <id>
            int id = atoi(ptr);
            if (id > 0) {
                cmd_get(id);
            } else {
                printf("Usage: get <id>\n");
            }
        } else if (strcmp(cmd, "list") == 0) {
            cmd_list();
        } else {
            printf("Unknown command: %s\n", cmd);
            printf("Type 'quit' to exit\n");
        }
        
        free(line);
    }
    
    // 정리
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(fd);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    
    secure_zero(master_key, MASTER_KEY_LEN);
    secure_zero(session_token, sizeof(session_token));
    
    printf("\nGoodbye!\n");
    
    return 0;
}

