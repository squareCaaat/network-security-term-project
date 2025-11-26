#!/bin/bash

# TLS 인증서 생성 스크립트
# 자체 서명 인증서 생성 (개발/테스트 목적)

CERTS_DIR="certs"
DAYS=365

echo "=== Generating TLS Certificates for Vault Server ==="

# 디렉토리 생성
mkdir -p $CERTS_DIR

# 1. CA 개인키 생성
echo "1. Generating CA private key..."
openssl genrsa -out $CERTS_DIR/ca.key 4096 2>/dev/null

# 2. CA 인증서 생성 (자체 서명)
echo "2. Generating CA certificate..."
openssl req -new -x509 -days $DAYS -key $CERTS_DIR/ca.key -out $CERTS_DIR/ca.crt \
    -subj "/C=KR/ST=Seoul/L=Seoul/O=Vault/OU=CA/CN=Vault Root CA" 2>/dev/null

# 3. 서버 개인키 생성
echo "3. Generating server private key..."
openssl genrsa -out $CERTS_DIR/server.key 2048 2>/dev/null

# 4. 서버 CSR 생성
echo "4. Generating server CSR..."
openssl req -new -key $CERTS_DIR/server.key -out $CERTS_DIR/server.csr \
    -subj "/C=KR/ST=Seoul/L=Seoul/O=Vault/OU=Server/CN=localhost" 2>/dev/null

# 5. SAN(Subject Alternative Name) 설정 파일 생성
cat > $CERTS_DIR/server_ext.cnf <<EOF
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = vault.local
IP.1 = 127.0.0.1
EOF

# 6. 서버 인증서 생성 (CA로 서명)
echo "5. Generating server certificate..."
openssl x509 -req -in $CERTS_DIR/server.csr -CA $CERTS_DIR/ca.crt -CAkey $CERTS_DIR/ca.key \
    -CAcreateserial -out $CERTS_DIR/server.crt -days $DAYS \
    -extfile $CERTS_DIR/server_ext.cnf 2>/dev/null

# 7. 클라이언트 개인키 생성 (mTLS용, 선택적)
echo "6. Generating client private key (for mTLS)..."
openssl genrsa -out $CERTS_DIR/client.key 2048 2>/dev/null

# 8. 클라이언트 CSR 생성
echo "7. Generating client CSR..."
openssl req -new -key $CERTS_DIR/client.key -out $CERTS_DIR/client.csr \
    -subj "/C=KR/ST=Seoul/L=Seoul/O=Vault/OU=Client/CN=client" 2>/dev/null

# 9. 클라이언트 인증서 생성
echo "8. Generating client certificate..."
openssl x509 -req -in $CERTS_DIR/client.csr -CA $CERTS_DIR/ca.crt -CAkey $CERTS_DIR/ca.key \
    -CAcreateserial -out $CERTS_DIR/client.crt -days $DAYS 2>/dev/null

# 정리
rm -f $CERTS_DIR/*.csr $CERTS_DIR/*.srl $CERTS_DIR/server_ext.cnf

# 권한 설정
chmod 600 $CERTS_DIR/*.key
chmod 644 $CERTS_DIR/*.crt

echo ""
echo "✓ Certificate generation complete!"
echo ""
echo "Generated files:"
echo "  - $CERTS_DIR/ca.crt        (CA certificate)"
echo "  - $CERTS_DIR/ca.key        (CA private key)"
echo "  - $CERTS_DIR/server.crt    (Server certificate)"
echo "  - $CERTS_DIR/server.key    (Server private key)"
echo "  - $CERTS_DIR/client.crt    (Client certificate, for mTLS)"
echo "  - $CERTS_DIR/client.key    (Client private key, for mTLS)"
echo ""
echo "Server certificate details:"
openssl x509 -in $CERTS_DIR/server.crt -noout -subject -issuer -dates 2>/dev/null
echo ""

