package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"time"

	_ "github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	pb "github.com/Aliobead234/microservices-demo/src/AOAmicroservice/functions"
)

const (
	serverAddr     = "localhost:50051"
	testUsername   = "alice@example.com"
	testPassword   = "Secur3P@ss!"
	testTOTPSecret = "JBSWY3DPEHPK3PXP"
	rsaKeyBits     = 2048
)

// randomUint64 – возвращает cryptographically-secure случайное uint64
func randomUint64() (uint64, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return 0, err
	}
	return new(big.Int).SetBytes(b).Uint64(), nil
}

// loadClientTLSCredentials настраивает TLS-клиент, доверяющий ca.crt
func loadClientTLSCredentials() (credentials.TransportCredentials, error) {
	pemCA, err := ioutil.ReadFile("../certs/ca.crt")
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemCA) {
		return nil, fmt.Errorf("failed to add CA cert")
	}
	tlsCfg := &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS13,
	}
	return credentials.NewTLS(tlsCfg), nil
}

// loadClientPrivateKey загружает RSA-приватный ключ из PEM (client.key)
func loadClientPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("invalid PEM for private key")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func main() {
	// 1) Настройка TLS
	creds, err := loadClientTLSCredentials()
	if err != nil {
		log.Fatalf("Failed to load client TLS credentials: %v", err)
	}
	conn, err := grpc.Dial(serverAddr, grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatalf("Failed to dial gRPC server: %v", err)
	}
	defer conn.Close()

	authClient := pb.NewAuthServiceClient(conn)
	txClient := pb.NewTransactionServiceClient(conn)

	// 2) Login (получаем access_jwt, refresh_token)
	//    Для простоты: отправляем тестовые данные, предполагая, что сервер выдаёт фиктивный JWT
	loginResp, err := authClient.Login(context.Background(), &pb.LoginRequest{
		Username: testUsername,
		Password: testPassword,
		TotpCode: "000000", // demo-код TOTP (сервер в этой демо всегда пропустит)
	})
	if err != nil {
		log.Fatalf("Login failed: %v", err)
	}
	accessJWT := loginResp.AccessJwt
	log.Printf("Login successful. Received access JWT: %s\n", accessJWT)

	// 3) Генерация/загрузка RSA-приватного ключа клиента
	privKey, err := loadClientPrivateKey("../certs/client.key")
	if err != nil {
		// Если файла нет, генерируем новый и записываем
		key, err2 := rsa.GenerateKey(rand.Reader, rsaKeyBits)
		if err2 != nil {
			log.Fatalf("Failed to generate RSA private key: %v", err2)
		}
		privKey = key
		privBytes := x509.MarshalPKCS1PrivateKey(privKey)
		pemBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}
		if err2 := ioutil.WriteFile("../certs/client.key", pem.EncodeToMemory(pemBlock), 0600); err2 != nil {
			log.Fatalf("Failed to write client.key: %v", err2)
		}
		log.Println("Generated and saved new RSA private key to ../certs/client.key")
	}
	pubKey := &privKey.PublicKey
	log.Printf("Client public key modulus (base64): %s\n", base64.StdEncoding.EncodeToString(pubKey.N.Bytes()))

	// 4) Формирование данных транзакции
	//    Поля: user_id|amount|currency|timestamp|nonce
	nowTs := uint64(time.Now().Unix())
	nonce, err := randomUint64()
	if err != nil {
		log.Fatalf("Failed to generate nonce: %v", err)
	}
	amount := 4.99
	currency := "USD"
	concat := fmt.Sprintf("%s|%.2f|%s|%d|%d", testUsername, amount, currency, nowTs, nonce)

	// 5) Вычисление SHA-256 хеша
	dataHash := sha256.Sum256([]byte(concat))

	// 6) RSA-подпись над хешем
	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, dataHash[:])
	if err != nil {
		log.Fatalf("Failed to sign data: %v", err)
	}

	// 7) Вызов ProcessTx
	md := metadata.Pairs("authorization", "Bearer "+accessJWT)
	ctx := metadata.NewOutgoingContext(context.Background(), md)
	txResp, err := txClient.ProcessTx(ctx, &pb.ProcessTxRequest{
		UserId:        testUsername,
		Amount:        amount,
		Currency:      currency,
		TimestampUnix: nowTs,
		Nonce:         nonce,
		Signature:     signature,
	})
	if err != nil {
		log.Fatalf("ProcessTx RPC failed: %v", err)
	}
	if !txResp.Success {
		log.Fatalf("Transaction rejected: %s", txResp.Message)
	}
	log.Printf("ProcessTx Success. TxID=%s, TxHash(base64)=%s, ServerTime=%d\n",
		txResp.TransactionId,
		base64.StdEncoding.EncodeToString(txResp.TxHash),
		txResp.ServerTimeUnix,
	)

	// 8) Вызов GetTxStatus для проверки
	statusResp, err := txClient.GetTxStatus(ctx, &pb.TxStatusRequest{
		UserId:        testUsername,
		TransactionId: txResp.TransactionId,
	})
	if err != nil {
		log.Fatalf("GetTxStatus RPC failed: %v", err)
	}
	log.Printf("GetTxStatus: Found=%v, Success=%v, Message=%s, Amount=%.2f %s, TxHash(base64)=%s\n",
		statusResp.Found,
		statusResp.Success,
		statusResp.Message,
		statusResp.Amount,
		statusResp.Currency,
		base64.StdEncoding.EncodeToString(statusResp.TxHash),
	)
}
