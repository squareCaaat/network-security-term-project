CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -I/usr/include/x86_64-linux-gnu
LDFLAGS = -L/usr/lib/x86_64-linux-gnu
LIBS = -lssl -lcrypto -lreadline

# 디렉토리
SRC_COMMON = src/common
SRC_SERVER = src/server
SRC_CLIENT = src/client
BUILD = build

# 공통 오브젝트 파일
COMMON_OBJS = $(BUILD)/protocol.o $(BUILD)/crypto_utils.o $(BUILD)/tls_common.o

# 서버 오브젝트 파일
SERVER_OBJS = $(BUILD)/auth_manager.o $(BUILD)/storage_manager.o $(BUILD)/server.o

# 클라이언트 오브젝트 파일
CLIENT_OBJS = $(BUILD)/client.o

# 타겟
all: directories server client

directories:
	@mkdir -p $(BUILD)
	@mkdir -p data
	@mkdir -p certs

server: $(COMMON_OBJS) $(SERVER_OBJS)
	$(CC) $(CFLAGS) -o server $^ $(LDFLAGS) $(LIBS)

client: $(COMMON_OBJS) $(CLIENT_OBJS)
	$(CC) $(CFLAGS) -o client $^ $(LDFLAGS) $(LIBS)

# 공통 모듈 컴파일
$(BUILD)/protocol.o: $(SRC_COMMON)/protocol.c $(SRC_COMMON)/protocol.h
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/crypto_utils.o: $(SRC_COMMON)/crypto_utils.c $(SRC_COMMON)/crypto_utils.h
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/tls_common.o: $(SRC_COMMON)/tls_common.c $(SRC_COMMON)/tls_common.h
	$(CC) $(CFLAGS) -c $< -o $@

# 서버 모듈 컴파일
$(BUILD)/auth_manager.o: $(SRC_SERVER)/auth_manager.c $(SRC_SERVER)/auth_manager.h
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/storage_manager.o: $(SRC_SERVER)/storage_manager.c $(SRC_SERVER)/storage_manager.h
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/server.o: $(SRC_SERVER)/server.c
	$(CC) $(CFLAGS) -c $< -o $@

# 클라이언트 모듈 컴파일
$(BUILD)/client.o: $(SRC_CLIENT)/client.c
	$(CC) $(CFLAGS) -c $< -o $@

# 인증서 생성
certs: directories
	@echo "Generating TLS certificates..."
	@./scripts/gen_certs.sh

# 정리
clean:
	rm -rf $(BUILD)
	rm -f server client

# 전체 정리 (데이터 포함)
cleanall: clean
	rm -rf data/*.db
	rm -rf certs/*

# 실행
run-server: server certs
	./server

run-client: client
	./client

.PHONY: all directories server client certs clean cleanall run-server run-client
