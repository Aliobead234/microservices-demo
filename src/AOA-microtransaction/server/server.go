package main

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	_ "strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	_ "google.golang.org/grpc/metadata"

	pb "github.com/Aliobead234/microservices-demo/src/AOAmicroservice/functions"
)

// -------------------------
// Константы и настройки
// -------------------------
const (
	jwtSecretKey       = "hmac_secret_change_me" // HS256 секрет (если понадобится JWT)
	jwtValidSeconds    = 90                      // 90 сек для access_jwt
	refreshTokenLength = 16                      // длина (в байтах) для refresh token

	testUsername   = "alice@example.com"
	testPassword   = "Secur3P@ss!"      // bcrypt-хешировать
	testTOTPSecret = "JBSWY3DPEHPK3PXP" // TOTP-секрет (Google Auth)
	rsaKeyBits     = 2048
	maxSkewSeconds = 20 // ±20 сек окно для timestamp
)

// -------------------------
// Структуры in-memory
// -------------------------
var (
	userDB   = make(map[string]*UserRecord) // user_id → UserRecord
	userDBMu sync.Mutex

	publicKeyStore   = make(map[string]*rsa.PublicKey) // user_id → public RSA key
	publicKeyStoreMu sync.Mutex

	nonceStore   = make(map[string]map[uint64]bool) // user_id → set(nonce)
	nonceStoreMu sync.Mutex

	txStore   = make(map[string]map[string]TxRecord) // user_id → map(txID → TxRecord)
	txStoreMu sync.Mutex

	aesKey   []byte // общий AES-256 ключ (32 байта)
	aesKeyMu sync.Mutex
)

// UserRecord – запись о пользователе (пароль, TOTP, publicKey)
type UserRecord struct {
	HashedPassword []byte
	TOTPSecret     string
	PublicKey      *rsa.PublicKey
	PrivateKey     *rsa.PrivateKey // только для теста/демо, на проде приватный хранится у клиента
}

// TxRecord – хранение деталей транзакции
type TxRecord struct {
	Success        bool
	Message        string
	Amount         float64
	Currency       string
	TimestampUnix  uint64
	TxHash         []byte
	ServerTimeUnix uint64
	EncPayload     string // AES-GCM шифрованный JSON или данные, если нужно
}

// -------------------------
// Утилиты для RSA
// -------------------------
func loadRSAPublicKey(pemPath string) (*rsa.PublicKey, error) {
	data, err := ioutil.ReadFile(pemPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("invalid PEM for public key")
	}
	pubIfc, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := pubIfc.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}
	return pub, nil
}

func loadRSAPrivateKey(pemPath string) (*rsa.PrivateKey, error) {
	data, err := ioutil.ReadFile(pemPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("invalid PEM for private key")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

// verifyRSASignature – проверяет подпись над данными (dataHash) с помощью pubKey
func verifyRSASignature(pubKey *rsa.PublicKey, dataHash, signature []byte) error {
	return rsa.VerifyPKCS1v15(pubKey, crypto.Hash(sha256.New().Size()), dataHash, signature)
}

// -------------------------
// Утилиты для AES-GCM
// -------------------------
func generateAESKey() ([]byte, error) {
	key := make([]byte, 32) // AES-256
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

func loadAESKey() ([]byte, error) {
	aesKeyMu.Lock()
	defer aesKeyMu.Unlock()
	if aesKey != nil {
		return aesKey, nil
	}
	key, err := generateAESKey()
	if err != nil {
		return nil, err
	}
	aesKey = key
	return aesKey, nil
}

// encryptAESGCM шифрует plaintext (в виде []byte) и возвращает результат base64
func encryptAESGCM(plaintext []byte) (string, error) {
	key, err := loadAESKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := aesgcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decryptAESGCM принимает base64-строку, расшифровывает её и возвращает []byte plaintext
func decryptAESGCM(cipherB64 string) ([]byte, error) {
	key, err := loadAESKey()
	if err != nil {
		return nil, err
	}
	data, err := base64.StdEncoding.DecodeString(cipherB64)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := aesgcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return aesgcm.Open(nil, nonce, ciphertext, nil)
}

// -------------------------
// Утилиты для JWT (опционально, если нужен AuthService)
// -------------------------
func hashPassword(plain string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
}

func checkPassword(hash []byte, plain string) bool {
	return bcrypt.CompareHashAndPassword(hash, []byte(plain)) == nil
}

// -------------------------
// AuthService (если требуется)
// -------------------------
type authServiceServer struct {
	pb.UnimplementedAuthServiceServer
}

func (s *authServiceServer) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	// Здесь можно расширить проверку: хеш пароля, TOTP-код и т.д.
	// Для краткости: возвращаем фиктивный access_jwt и refresh_token.
	return &pb.LoginResponse{
		AccessJwt:     "fake_jwt_token",
		RefreshToken:  "fake_refresh_token",
		ExpiresAtUnix: uint64(time.Now().Add(90 * time.Second).Unix()),
	}, nil
}

func (s *authServiceServer) RefreshToken(ctx context.Context, req *pb.RefreshRequest) (*pb.RefreshResponse, error) {
	return &pb.RefreshResponse{
		AccessJwt:     "new_fake_jwt",
		RefreshToken:  "new_fake_refresh_token",
		ExpiresAtUnix: uint64(time.Now().Add(90 * time.Second).Unix()),
	}, nil
}

// -------------------------
// TransactionService
// -------------------------
type transactionServiceServer struct {
	pb.UnimplementedTransactionServiceServer
}

func (s *transactionServiceServer) ProcessTx(ctx context.Context, req *pb.ProcessTxRequest) (*pb.ProcessTxResponse, error) {
	// 1) Проверка JWT в метаданных (опционально): если не нужна аутентификация, пропустить

	// 2) Вычислить SHA-256 хеш по строке "user_id|amount|currency|timestamp|nonce"
	concat := fmt.Sprintf("%s|%.2f|%s|%d|%d",
		req.UserId, req.Amount, req.Currency, req.TimestampUnix, req.Nonce)
	dataHash := sha256.Sum256([]byte(concat))

	// 3) Проверить подпись RSA
	publicKeyStoreMu.Lock()
	pubKey, exists := publicKeyStore[req.UserId]
	publicKeyStoreMu.Unlock()
	if !exists {
		return &pb.ProcessTxResponse{
			Success: false,
			Message: "Public key for user not found",
		}, nil
	}
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, dataHash[:], req.Signature); err != nil {
		return &pb.ProcessTxResponse{
			Success: false,
			Message: "Invalid RSA signature",
		}, nil
	}

	// 4) Проверить timestamp (±maxSkewSeconds) и nonce (replay protection)
	now := uint64(time.Now().Unix())
	if req.TimestampUnix+uint64(maxSkewSeconds) < now || req.TimestampUnix > now+uint64(maxSkewSeconds) {
		return &pb.ProcessTxResponse{
			Success: false,
			Message: "Timestamp outside allowed window",
		}, nil
	}
	nonceStoreMu.Lock()
	if _, ok := nonceStore[req.UserId]; !ok {
		nonceStore[req.UserId] = make(map[uint64]bool)
	}
	if nonceStore[req.UserId][req.Nonce] {
		nonceStoreMu.Unlock()
		return &pb.ProcessTxResponse{
			Success: false,
			Message: "Nonce replay detected",
		}, nil
	}
	nonceStore[req.UserId][req.Nonce] = true
	nonceStoreMu.Unlock()

	// 5) Генерируем transaction_id и храним TxRecord
	txID := uuid.New().String()
	serverTime := uint64(time.Now().Unix())

	// Здесь можно зашифровать «payload» AES-GCM, если нужно
	payload := fmt.Sprintf(`{"user_id":"%s","amount":%.2f,"currency":"%s","timestamp":%d,"nonce":%d}`,
		req.UserId, req.Amount, req.Currency, req.TimestampUnix, req.Nonce)
	encPayload, err := encryptAESGCM([]byte(payload))
	if err != nil {
		return &pb.ProcessTxResponse{
			Success: false,
			Message: "AES encrypt error",
		}, nil
	}

	record := TxRecord{
		Success:        true,
		Message:        "Transaction accepted",
		Amount:         req.Amount,
		Currency:       req.Currency,
		TimestampUnix:  req.TimestampUnix,
		TxHash:         dataHash[:],
		ServerTimeUnix: serverTime,
		EncPayload:     encPayload,
	}
	txStoreMu.Lock()
	if _, ok := txStore[req.UserId]; !ok {
		txStore[req.UserId] = make(map[string]TxRecord)
	}
	txStore[req.UserId][txID] = record
	txStoreMu.Unlock()

	return &pb.ProcessTxResponse{
		Success:        true,
		Message:        "Accepted",
		TransactionId:  txID,
		TxHash:         dataHash[:],
		ServerTimeUnix: serverTime,
	}, nil
}

func (s *transactionServiceServer) GetTxStatus(ctx context.Context, req *pb.TxStatusRequest) (*pb.TxStatusResponse, error) {
	// 1) Если нужна проверка JWT, здесь повторить (для краткости пропускаем)

	txStoreMu.Lock()
	userTxs, found := txStore[req.UserId]
	txStoreMu.Unlock()
	if !found {
		return &pb.TxStatusResponse{
			Found:   false,
			Success: false,
			Message: "No transactions for user",
		}, nil
	}
	rec, ok := userTxs[req.TransactionId]
	if !ok {
		return &pb.TxStatusResponse{
			Found:   false,
			Success: false,
			Message: "Transaction ID not found",
		}, nil
	}
	return &pb.TxStatusResponse{
		Found:         true,
		Success:       rec.Success,
		Message:       rec.Message,
		Amount:        rec.Amount,
		Currency:      rec.Currency,
		TimestampUnix: rec.TimestampUnix,
		TxHash:        rec.TxHash,
	}, nil
}

// -------------------------
// Загрузка TLS для gRPC
// -------------------------
func loadTLSCredentials() (credentials.TransportCredentials, error) {
	serverCert, err := tls.LoadX509KeyPair("../certs/server.crt", "../certs/server.key")
	if err != nil {
		return nil, err
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.NoClientCert,
	}
	return credentials.NewTLS(config), nil
}

// -------------------------
// Инициализация test-user + RSA keys
// -------------------------
func initTestUser() {
	userDBMu.Lock()
	defer userDBMu.Unlock()

	hashedPw, _ := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.DefaultCost)

	priv, pub, _ := func() (*rsa.PrivateKey, *rsa.PublicKey, error) {
		key, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
		if err != nil {
			return nil, nil, err
		}
		return key, &key.PublicKey, nil
	}()

	userDB[testUsername] = &UserRecord{
		HashedPassword: hashedPw,
		TOTPSecret:     testTOTPSecret,
		PublicKey:      pub,
		PrivateKey:     priv,
	}
	publicKeyStoreMu.Lock()
	publicKeyStore[testUsername] = pub
	publicKeyStoreMu.Unlock()
	log.Printf("Initialized test user '%s'; public key modulus (base64): %s\n",
		testUsername, base64.StdEncoding.EncodeToString(pub.N.Bytes()))
}

func main() {
	initTestUser()

	creds, err := loadTLSCredentials()
	if err != nil {
		log.Fatalf("Failed to load TLS: %v", err)
	}
	grpcServer := grpc.NewServer(grpc.Creds(creds))

	pb.RegisterAuthServiceServer(grpcServer, &authServiceServer{})
	pb.RegisterTransactionServiceServer(grpcServer, &transactionServiceServer{})

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	log.Println("gRPC server listening on :50051 (TLS enabled)")
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
