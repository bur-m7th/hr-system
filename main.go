package main

// ═══════════════════════════════════════════════════════════════
// SECURE HR PAYROLL SYSTEM - SEGMENT 1 OF 3
// Includes: Imports, Structs, Globals, Encryption, Security Utils
// ═══════════════════════════════════════════════════════════════

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/png"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
)

// ================= STRUCTS =================

type Employee struct {
	ID             int     `json:"id"`
	Name           string  `json:"name"`
	Email          string  `json:"email"`
	PhoneNumber    string  `json:"phoneNumber"`
	Address        string  `json:"address"`
	NationalID     string  `json:"nationalId"`
	ExcludedMonths string  `json:"excludedMonths"`
	ContractID     int     `json:"contractId"`
	Position       string  `json:"position"`
	Department     string  `json:"department"`
	BaseSalary     float64 `json:"baseSalary"`
	ContractStart  string  `json:"contractStart"`
	ContractEnd    string  `json:"contractEnd"`
}

type Contract struct {
	ID         int     `json:"id"`
	EmployeeID int     `json:"employeeId"`
	Position   string  `json:"position"`
	Department string  `json:"department"`
	BaseSalary float64 `json:"baseSalary"`
	StartDate  string  `json:"startDate"`
	EndDate    string  `json:"endDate"`
	IsActive   bool    `json:"isActive"`
}

type PaymentRecord struct {
	ID           int     `json:"id"`
	EmployeeID   int     `json:"employeeId"`
	EmployeeName string  `json:"employeeName"`
	PayPeriod    string  `json:"payPeriod"`
	BaseSalary   float64 `json:"baseSalary"`
	Bonus        float64 `json:"bonus"`
	Deductions   float64 `json:"deductions"`
	NetSalary    float64 `json:"netSalary"`
	GeneratedAt  string  `json:"generatedAt"`
	DocumentPath string  `json:"documentPath"`
}

type EmployeeStats struct {
	TotalPaid          float64        `json:"totalPaid"`
	PastUnpaid         float64        `json:"pastUnpaid"`
	TotalContractValue float64        `json:"totalContractValue"`
	ToBePaid           float64        `json:"toBePaid"`
	Timeline           []TimelineItem `json:"timeline"`
}

type TimelineItem struct {
	Month     string  `json:"month"`
	Status    string  `json:"status"`
	Amount    float64 `json:"amount"`
	PaymentID int     `json:"paymentId,omitempty"`
	DocPath   string  `json:"docPath,omitempty"`
	Position  string  `json:"position,omitempty"`
}

type User struct {
	ID           int    `json:"id"`
	Username     string `json:"username"`
	PasswordHash string `json:"-"`
	TwoFASecret  string `json:"-"`
	TwoFAEnabled bool   `json:"twoFaEnabled"`
}

type ChangePasswordReq struct {
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword"`
	TwoFACode   string `json:"twoFaCode"`
}

type TemplateFile struct {
	Name      string `json:"name"`
	IsActive  bool   `json:"isActive"`
	UpdatedAt string `json:"updatedAt"`
}

// ================= GLOBALS =================

var (
	encryptionKey []byte
	sessions      = make(map[string]int)
	sessionMutex  sync.RWMutex
	db            *sql.DB
	pending2FA    = make(map[string]int)
	loginLimiters = make(map[string]*rate.Limiter)
	limiterMutex  sync.RWMutex
)

// ================= ENCRYPTION FUNCTIONS =================

func initEncryptionKey() error {
	keyStr := os.Getenv("HR_ENCRYPTION_KEY")
	if keyStr != "" {
		decoded, err := base64.StdEncoding.DecodeString(keyStr)
		if err == nil && len(decoded) == 32 {
			encryptionKey = decoded
			log.Println("✓ Loaded encryption key from environment")
			return nil
		}
		log.Println("⚠️  Invalid encryption key in environment, using file")
	}

	keyFile := "./db/.encryption_key"
	if data, err := os.ReadFile(keyFile); err == nil {
		if len(data) == 32 {
			encryptionKey = data
			log.Println("✓ Loaded existing encryption key from file")
			return nil
		}
	}

	encryptionKey = make([]byte, 32)
	if _, err := rand.Read(encryptionKey); err != nil {
		return err
	}

	os.MkdirAll("./db", 0700)
	if err := os.WriteFile(keyFile, encryptionKey, 0600); err != nil {
		return err
	}

	log.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	log.Println("⚠️  NEW ENCRYPTION KEY GENERATED!")
	log.Println("⚠️  CRITICAL: BACKUP THIS FILE IMMEDIATELY:")
	log.Println("    ./db/.encryption_key")
	log.Println("⚠️  WITHOUT THIS FILE, ALL DATA WILL BE LOST!")
	log.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	return nil
}

func encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decrypt(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertextBytes := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// ================= RATE LIMITING =================

func getLoginLimiter(ip string) *rate.Limiter {
	limiterMutex.Lock()
	defer limiterMutex.Unlock()
	if limiter, exists := loginLimiters[ip]; exists {
		return limiter
	}
	limiter := rate.NewLimiter(rate.Every(time.Minute), 5)
	loginLimiters[ip] = limiter
	return limiter
}

func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		limiter := getLoginLimiter(ip)
		if !limiter.Allow() {
			log.Printf("⚠️  Rate limit exceeded from IP: %s", ip)
			http.Error(w, "Too many attempts. Please try again later.", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// ================= INPUT VALIDATION =================

var (
	emailRegex    = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	filenameRegex = regexp.MustCompile(`^[a-zA-Z0-9._\-]+\.docx$`)
)

func validateEmail(email string) bool {
	return email == "" || (len(email) < 200 && emailRegex.MatchString(email))
}

func validateFilename(filename string) bool {
	if strings.Contains(filename, "..") || strings.Contains(filename, "/") ||
		strings.Contains(filename, "\\") || len(filename) > 100 {
		return false
	}
	return filenameRegex.MatchString(filename)
}

func validateString(s string, minLen, maxLen int) bool {
	length := len(s)
	return length >= minLen && length <= maxLen
}

func validatePassword(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	if len(password) > 128 {
		return fmt.Errorf("password too long")
	}
	return nil
}

func validateEmployee(emp *Employee) error {
	if !validateString(emp.Name, 1, 200) {
		return fmt.Errorf("invalid name length")
	}
	if !validateEmail(emp.Email) {
		return fmt.Errorf("invalid email format")
	}
	if len(emp.PhoneNumber) > 50 {
		return fmt.Errorf("phone number too long")
	}
	if len(emp.Address) > 500 {
		return fmt.Errorf("address too long")
	}
	if len(emp.NationalID) > 50 {
		return fmt.Errorf("national ID too long")
	}
	if emp.BaseSalary < 0 || emp.BaseSalary > 10000000 {
		return fmt.Errorf("invalid salary amount")
	}
	if !validateString(emp.Position, 1, 100) {
		return fmt.Errorf("invalid position")
	}
	if !validateString(emp.Department, 1, 100) {
		return fmt.Errorf("invalid department")
	}
	return nil
}

func sanitizeInput(input string) string {
	return strings.TrimSpace(input)
}

// ================= AUDIT LOGGING =================

func auditLog(userID int, action string, details string) {
	logEntry := fmt.Sprintf("[AUDIT] %s | UserID: %d | Action: %s | Details: %s",
		time.Now().Format("2006-01-02 15:04:05"), userID, action, details)
	log.Println(logEntry)
	f, err := os.OpenFile("./db/audit.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err == nil {
		defer f.Close()
		f.WriteString(logEntry + "\n")
	}
}

// ================= DATABASE INIT =================

func initDB() error {
	os.MkdirAll("./db", os.ModePerm)
	var err error
	db, err = sql.Open("sqlite3", "./db/hrpayroll.db")
	if err != nil {
		return err
	}

	queries := []string{
		`CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            address TEXT,
            national_id TEXT,
            excluded_months TEXT DEFAULT ''
        )`,
		`CREATE TABLE IF NOT EXISTS contracts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id INTEGER NOT NULL,
            position TEXT NOT NULL,
            department TEXT NOT NULL,
            base_salary REAL NOT NULL,
            start_date TEXT NOT NULL,
            end_date TEXT,
            is_active BOOLEAN DEFAULT 1,
            FOREIGN KEY (employee_id) REFERENCES employees(id)
        )`,
		`CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id INTEGER NOT NULL,
            employee_name TEXT NOT NULL,
            pay_period TEXT NOT NULL,
            base_salary REAL NOT NULL,
            bonus REAL DEFAULT 0,
            deductions REAL DEFAULT 0,
            net_salary REAL NOT NULL,
            generated_at TEXT NOT NULL,
            document_path TEXT,
            FOREIGN KEY (employee_id) REFERENCES employees(id)
        )`,
		`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            totp_secret TEXT,
            totp_enabled BOOLEAN DEFAULT 0
        )`,
	}

	for _, q := range queries {
		if _, err := db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

// ================= MIDDLEWARE & SECURITY =================

func enableCORS(w http.ResponseWriter) {
	origin := os.Getenv("ALLOWED_ORIGIN")
	if origin == "" {
		origin = "http://localhost:8080"
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	if os.Getenv("PRODUCTION") == "true" {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
		if r.Method == "OPTIONS" {
			enableCORS(w)
			w.WriteHeader(http.StatusOK)
			return
		}
		c, err := r.Cookie("session_token")
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		sessionMutex.RLock()
		_, exists := sessions[c.Value]
		sessionMutex.RUnlock()
		if !exists {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func getUserID(r *http.Request) int {
	c, _ := r.Cookie("session_token")
	if c == nil {
		return 0
	}
	sessionMutex.RLock()
	defer sessionMutex.RUnlock()
	return sessions[c.Value]
}

func createSession(w http.ResponseWriter, userID int) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		log.Printf("❌ Failed to generate session token: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	token := base64.URLEncoding.EncodeToString(tokenBytes)
	sessionMutex.Lock()
	sessions[token] = userID
	sessionMutex.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    token,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Secure:   os.Getenv("PRODUCTION") == "true",
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})
	auditLog(userID, "SESSION_CREATED", fmt.Sprintf("Token: %s...", token[:8]))
}

// ═══════════════════════════════════════════════════════════════
// END OF SEGMENT 1
// Continue with SEGMENT 2 for Authentication & Employee Management
// ═══════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════
// SECURE HR PAYROLL SYSTEM - SEGMENT 2 OF 3
// Includes: Auth Functions, Employee Management, Contract Operations
// APPEND THIS TO SEGMENT 1
// ═══════════════════════════════════════════════════════════════

// ================= AUTHENTICATION =================

func checkSystemSetup(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	var count int
	db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	json.NewEncoder(w).Encode(map[string]bool{"isSetup": count > 0})
}

func registerUser(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	if r.Method == "OPTIONS" {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)
	var count int
	db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if count > 0 {
		http.Error(w, "System already setup", http.StatusForbidden)
		return
	}
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	creds.Username = sanitizeInput(creds.Username)
	if !validateString(creds.Username, 3, 50) {
		http.Error(w, "Username must be 3-50 characters", http.StatusBadRequest)
		return
	}
	if err := validatePassword(creds.Password); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	hashed, _ := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
	db.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", creds.Username, string(hashed))
	auditLog(0, "SYSTEM_SETUP", fmt.Sprintf("Owner account created: %s", creds.Username))
	json.NewEncoder(w).Encode(map[string]string{"message": "Setup complete"})
}

func createUser(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	if r.Method != "POST" {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	creds.Username = sanitizeInput(creds.Username)
	if !validateString(creds.Username, 3, 50) {
		http.Error(w, "Username must be 3-50 characters", http.StatusBadRequest)
		return
	}
	if err := validatePassword(creds.Password); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	hashed, _ := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
	_, err := db.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", creds.Username, string(hashed))
	if err != nil {
		http.Error(w, "Username already exists", http.StatusConflict)
		return
	}
	userID := getUserID(r)
	auditLog(userID, "USER_CREATED", fmt.Sprintf("New user: %s", creds.Username))
	w.WriteHeader(http.StatusCreated)
}

func login(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	if r.Method == "OPTIONS" {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	creds.Username = sanitizeInput(creds.Username)
	if !validateString(creds.Username, 1, 100) {
		auditLog(0, "LOGIN_FAILED", fmt.Sprintf("Invalid username format, IP: %s", r.RemoteAddr))
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	var user User
	err := db.QueryRow("SELECT id, username, password_hash, COALESCE(totp_secret, ''), totp_enabled FROM users WHERE username=?", creds.Username).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.TwoFASecret, &user.TwoFAEnabled)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(creds.Password)) != nil {
		auditLog(0, "LOGIN_FAILED", fmt.Sprintf("Username: %s, IP: %s", creds.Username, r.RemoteAddr))
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	if user.TwoFAEnabled {
		tokenBytes := make([]byte, 32)
		rand.Read(tokenBytes)
		tempToken := base64.URLEncoding.EncodeToString(tokenBytes)
		sessionMutex.Lock()
		pending2FA[tempToken] = user.ID
		sessionMutex.Unlock()
		auditLog(user.ID, "LOGIN_2FA_REQUIRED", fmt.Sprintf("IP: %s", r.RemoteAddr))
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "2fa_required", "tempToken": tempToken})
		return
	}
	createSession(w, user.ID)
	auditLog(user.ID, "LOGIN_SUCCESS", fmt.Sprintf("IP: %s", r.RemoteAddr))
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func verify2FALogin(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	if r.Method == "OPTIONS" {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)
	var req struct {
		TempToken string `json:"tempToken"`
		Code      string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	sessionMutex.RLock()
	userID, ok := pending2FA[req.TempToken]
	sessionMutex.RUnlock()
	if !ok {
		auditLog(0, "2FA_FAILED", "Invalid temp token")
		http.Error(w, "Invalid session", http.StatusUnauthorized)
		return
	}
	var secret string
	db.QueryRow("SELECT totp_secret FROM users WHERE id=?", userID).Scan(&secret)
	if !totp.Validate(req.Code, secret) {
		auditLog(userID, "2FA_FAILED", "Invalid code")
		http.Error(w, "Invalid code", http.StatusUnauthorized)
		return
	}
	sessionMutex.Lock()
	delete(pending2FA, req.TempToken)
	sessionMutex.Unlock()
	createSession(w, userID)
	auditLog(userID, "LOGIN_SUCCESS_2FA", "2FA verified")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func checkAuthStatus(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	c, err := r.Cookie("session_token")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"loggedIn": false})
		return
	}
	sessionMutex.RLock()
	userID, exists := sessions[c.Value]
	sessionMutex.RUnlock()
	if !exists {
		json.NewEncoder(w).Encode(map[string]interface{}{"loggedIn": false})
		return
	}
	var username string
	var enabled bool
	db.QueryRow("SELECT username, totp_enabled FROM users WHERE id=?", userID).Scan(&username, &enabled)
	json.NewEncoder(w).Encode(map[string]interface{}{"loggedIn": true, "username": username, "2faEnabled": enabled})
}

func logout(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	c, _ := r.Cookie("session_token")
	if c != nil {
		sessionMutex.Lock()
		userID := sessions[c.Value]
		delete(sessions, c.Value)
		sessionMutex.Unlock()
		auditLog(userID, "LOGOUT", "Session terminated")
	}
	http.SetCookie(w, &http.Cookie{Name: "session_token", Value: "", MaxAge: -1, Path: "/"})
	w.WriteHeader(http.StatusOK)
}

func changePassword(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	userID := getUserID(r)
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)
	var req ChangePasswordReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if err := validatePassword(req.NewPassword); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var currentHash, secret string
	var twoFAEnabled bool
	db.QueryRow("SELECT password_hash, COALESCE(totp_secret, ''), totp_enabled FROM users WHERE id=?", userID).Scan(&currentHash, &secret, &twoFAEnabled)
	if bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(req.OldPassword)) != nil {
		auditLog(userID, "PASSWORD_CHANGE_FAILED", "Incorrect old password")
		http.Error(w, "Incorrect old password", http.StatusUnauthorized)
		return
	}
	if twoFAEnabled && !totp.Validate(req.TwoFACode, secret) {
		auditLog(userID, "PASSWORD_CHANGE_FAILED", "Invalid 2FA code")
		http.Error(w, "Invalid 2FA code", http.StatusUnauthorized)
		return
	}
	newHash, _ := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	db.Exec("UPDATE users SET password_hash=? WHERE id=?", string(newHash), userID)
	auditLog(userID, "PASSWORD_CHANGED", "Password updated successfully")
	json.NewEncoder(w).Encode(map[string]string{"message": "Password updated"})
}

func deleteAccount(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	userID := getUserID(r)
	db.Exec("DELETE FROM users WHERE id=?", userID)
	auditLog(userID, "ACCOUNT_DELETED", "User deleted their account")
	logout(w, r)
}

func generate2FA(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	key, _ := totp.Generate(totp.GenerateOpts{Issuer: "HRPayroll", AccountName: "User"})
	var buf bytes.Buffer
	img, _ := key.Image(200, 200)
	png.Encode(&buf, img)
	userID := getUserID(r)
	auditLog(userID, "2FA_GENERATED", "QR code generated")
	json.NewEncoder(w).Encode(map[string]string{"secret": key.Secret(), "qr": base64.StdEncoding.EncodeToString(buf.Bytes())})
}

func enable2FA(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	userID := getUserID(r)
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)
	var req struct {
		Secret string `json:"secret"`
		Code   string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if !totp.Validate(req.Code, req.Secret) {
		auditLog(userID, "2FA_ENABLE_FAILED", "Invalid verification code")
		http.Error(w, "Invalid code", http.StatusBadRequest)
		return
	}
	db.Exec("UPDATE users SET totp_secret=?, totp_enabled=1 WHERE id=?", req.Secret, userID)
	auditLog(userID, "2FA_ENABLED", "Two-factor authentication enabled")
	w.WriteHeader(http.StatusOK)
}

// ================= EMPLOYEE MANAGEMENT WITH ENCRYPTION =================

func getEmployees(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	dept := r.URL.Query().Get("department")
	pos := r.URL.Query().Get("position")
	search := r.URL.Query().Get("search")

	query := `SELECT e.id, e.name, e.email, e.phone, e.address, e.national_id, e.excluded_months,
               c.id, c.position, c.department, c.base_salary, c.start_date, COALESCE(c.end_date, '')
        FROM employees e JOIN contracts c ON e.id = c.employee_id WHERE c.is_active = 1`
	args := []interface{}{}
	if dept != "" {
		query += " AND c.department = ?"
		args = append(args, dept)
	}
	if pos != "" {
		query += " AND c.position = ?"
		args = append(args, pos)
	}
	query += " ORDER BY e.name"

	rows, err := db.Query(query, args...)
	if err != nil {
		log.Printf("Error querying employees: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var employees []Employee
	for rows.Next() {
		var emp Employee
		var encName, encEmail, encPhone, encAddr, encNatID sql.NullString
		err := rows.Scan(&emp.ID, &encName, &encEmail, &encPhone, &encAddr, &encNatID, &emp.ExcludedMonths,
			&emp.ContractID, &emp.Position, &emp.Department, &emp.BaseSalary, &emp.ContractStart, &emp.ContractEnd)
		if err != nil {
			continue
		}
		emp.Name, _ = decrypt(encName.String)
		emp.Email, _ = decrypt(encEmail.String)
		emp.PhoneNumber, _ = decrypt(encPhone.String)
		emp.Address, _ = decrypt(encAddr.String)
		emp.NationalID, _ = decrypt(encNatID.String)

		if search != "" {
			if !strings.Contains(strings.ToLower(emp.Name), strings.ToLower(search)) &&
				!strings.Contains(strings.ToLower(emp.Email), strings.ToLower(search)) {
				continue
			}
		}
		employees = append(employees, emp)
	}
	if employees == nil {
		employees = []Employee{}
	}
	json.NewEncoder(w).Encode(employees)
}

func addEmployee(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	if r.Method != "POST" {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)
	var emp Employee
	if err := json.NewDecoder(r.Body).Decode(&emp); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	emp.Name = sanitizeInput(emp.Name)
	emp.Email = sanitizeInput(emp.Email)
	emp.PhoneNumber = sanitizeInput(emp.PhoneNumber)
	emp.Address = sanitizeInput(emp.Address)
	emp.NationalID = sanitizeInput(emp.NationalID)
	emp.Position = sanitizeInput(emp.Position)
	emp.Department = sanitizeInput(emp.Department)

	if err := validateEmployee(&emp); err != nil {
		http.Error(w, "Validation error: "+err.Error(), http.StatusBadRequest)
		return
	}

	encName, _ := encrypt(emp.Name)
	encEmail, _ := encrypt(emp.Email)
	encPhone, _ := encrypt(emp.PhoneNumber)
	encAddr, _ := encrypt(emp.Address)
	encNatID, _ := encrypt(emp.NationalID)

	tx, _ := db.Begin()
	res, err := tx.Exec(`INSERT INTO employees (name, email, phone, address, national_id, excluded_months) VALUES (?, ?, ?, ?, ?, ?)`,
		encName, encEmail, encPhone, encAddr, encNatID, emp.ExcludedMonths)
	if err != nil {
		tx.Rollback()
		log.Printf("Error adding employee: %v", err)
		http.Error(w, "Failed to add employee", http.StatusInternalServerError)
		return
	}
	empID, _ := res.LastInsertId()
	_, err = tx.Exec(`INSERT INTO contracts (employee_id, position, department, base_salary, start_date, end_date, is_active) VALUES (?, ?, ?, ?, ?, ?, 1)`,
		empID, emp.Position, emp.Department, emp.BaseSalary, emp.ContractStart, nil)
	if err != nil {
		tx.Rollback()
		log.Printf("Error creating contract: %v", err)
		http.Error(w, "Failed to create contract", http.StatusInternalServerError)
		return
	}
	tx.Commit()
	emp.ID = int(empID)
	userID := getUserID(r)
	auditLog(userID, "EMPLOYEE_ADDED", fmt.Sprintf("Employee ID: %d, Name: %s", emp.ID, emp.Name))
	json.NewEncoder(w).Encode(emp)
}

func updateEmployee(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	if r.Method != "PUT" {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)
	var emp Employee
	if err := json.NewDecoder(r.Body).Decode(&emp); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	emp.Name = sanitizeInput(emp.Name)
	emp.Email = sanitizeInput(emp.Email)
	emp.PhoneNumber = sanitizeInput(emp.PhoneNumber)
	emp.Address = sanitizeInput(emp.Address)
	emp.NationalID = sanitizeInput(emp.NationalID)
	emp.Position = sanitizeInput(emp.Position)
	emp.Department = sanitizeInput(emp.Department)

	if err := validateEmployee(&emp); err != nil {
		http.Error(w, "Validation error: "+err.Error(), http.StatusBadRequest)
		return
	}

	encName, _ := encrypt(emp.Name)
	encEmail, _ := encrypt(emp.Email)
	encPhone, _ := encrypt(emp.PhoneNumber)
	encAddr, _ := encrypt(emp.Address)
	encNatID, _ := encrypt(emp.NationalID)

	tx, _ := db.Begin()
	_, err := tx.Exec(`UPDATE employees SET name=?, email=?, phone=?, address=?, national_id=?, excluded_months=? WHERE id=?`,
		encName, encEmail, encPhone, encAddr, encNatID, emp.ExcludedMonths, emp.ID)
	if err != nil {
		tx.Rollback()
		log.Printf("Error updating employee: %v", err)
		http.Error(w, "Failed to update employee", http.StatusInternalServerError)
		return
	}
	if emp.ContractID == 0 {
		err = tx.QueryRow("SELECT id FROM contracts WHERE employee_id=? AND is_active=1", emp.ID).Scan(&emp.ContractID)
		if err != nil {
			tx.Rollback()
			http.Error(w, "No active contract found", http.StatusNotFound)
			return
		}
	}
	_, err = tx.Exec(`UPDATE contracts SET position=?, department=?, base_salary=?, start_date=?, end_date=? WHERE id=? AND employee_id=?`,
		emp.Position, emp.Department, emp.BaseSalary, emp.ContractStart, emp.ContractEnd, emp.ContractID, emp.ID)
	if err != nil {
		tx.Rollback()
		log.Printf("Error updating contract: %v", err)
		http.Error(w, "Failed to update contract", http.StatusInternalServerError)
		return
	}
	if err := tx.Commit(); err != nil {
		http.Error(w, "Failed to commit changes", http.StatusInternalServerError)
		return
	}
	userID := getUserID(r)
	auditLog(userID, "EMPLOYEE_UPDATED", fmt.Sprintf("Employee ID: %d", emp.ID))
	json.NewEncoder(w).Encode(emp)
}

func renewContract(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	if r.Method != "POST" {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)
	var req struct {
		EmployeeID int     `json:"employeeId"`
		NewSalary  float64 `json:"newSalary"`
		NewPos     string  `json:"newPosition"`
		NewDept    string  `json:"newDepartment"`
		StartDate  string  `json:"startDate"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	req.NewPos = sanitizeInput(req.NewPos)
	req.NewDept = sanitizeInput(req.NewDept)
	if !validateString(req.NewPos, 1, 100) || !validateString(req.NewDept, 1, 100) {
		http.Error(w, "Invalid position or department", http.StatusBadRequest)
		return
	}
	if req.NewSalary < 0 || req.NewSalary > 10000000 {
		http.Error(w, "Invalid salary", http.StatusBadRequest)
		return
	}
	tx, _ := db.Begin()
	newStart, _ := time.Parse("2006-01-02", req.StartDate)
	endDate := newStart.AddDate(0, 0, -1).Format("2006-01-02")
	_, err := tx.Exec("UPDATE contracts SET is_active=0, end_date=? WHERE employee_id=? AND is_active=1", endDate, req.EmployeeID)
	if err != nil {
		tx.Rollback()
		log.Printf("Error closing old contract: %v", err)
		http.Error(w, "Failed to close old contract", http.StatusInternalServerError)
		return
	}
	_, err = tx.Exec(`INSERT INTO contracts (employee_id, position, department, base_salary, start_date, is_active) VALUES (?, ?, ?, ?, ?, 1)`,
		req.EmployeeID, req.NewPos, req.NewDept, req.NewSalary, req.StartDate)
	if err != nil {
		tx.Rollback()
		log.Printf("Error creating new contract: %v", err)
		http.Error(w, "Failed to create new contract", http.StatusInternalServerError)
		return
	}
	tx.Commit()
	userID := getUserID(r)
	auditLog(userID, "CONTRACT_RENEWED", fmt.Sprintf("Employee ID: %d", req.EmployeeID))
	w.WriteHeader(http.StatusOK)
}

func deleteEmployee(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	if r.Method != "DELETE" {
		return
	}
	id := r.URL.Query().Get("id")
	empID, err := strconv.Atoi(id)
	if err != nil || empID < 1 {
		http.Error(w, "Invalid employee ID", http.StatusBadRequest)
		return
	}
	db.Exec("DELETE FROM payments WHERE employee_id=?", id)
	db.Exec("DELETE FROM contracts WHERE employee_id=?", id)
	db.Exec("DELETE FROM employees WHERE id=?", id)
	userID := getUserID(r)
	auditLog(userID, "EMPLOYEE_DELETED", fmt.Sprintf("Employee ID: %d", empID))
	w.WriteHeader(http.StatusOK)
}

func bulkExcludeMonths(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	if r.Method != "POST" {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)
	var req struct {
		EmployeeID int      `json:"employeeId"`
		Months     []string `json:"months"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	var currentExcluded string
	db.QueryRow("SELECT COALESCE(excluded_months, '') FROM employees WHERE id=?", req.EmployeeID).Scan(&currentExcluded)
	parts := []string{}
	if currentExcluded != "" {
		parts = strings.Split(currentExcluded, ",")
	}
	existing := make(map[string]bool)
	for _, p := range parts {
		existing[p] = true
	}
	for _, m := range req.Months {
		if !existing[m] {
			parts = append(parts, m)
		}
	}
	newExcluded := strings.Join(parts, ",")
	db.Exec("UPDATE employees SET excluded_months=? WHERE id=?", newExcluded, req.EmployeeID)
	userID := getUserID(r)
	auditLog(userID, "MONTHS_EXCLUDED", fmt.Sprintf("Employee ID: %d, Months: %s", req.EmployeeID, newExcluded))
	w.WriteHeader(http.StatusOK)
}

func getDepartments(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	rows, err := db.Query("SELECT DISTINCT department FROM contracts WHERE is_active=1 ORDER BY department")
	if err != nil {
		log.Printf("Error querying departments: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var d []string
	for rows.Next() {
		var s string
		rows.Scan(&s)
		d = append(d, s)
	}
	if d == nil {
		d = []string{}
	}
	json.NewEncoder(w).Encode(d)
}

func getPositions(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	rows, err := db.Query("SELECT DISTINCT position FROM contracts WHERE is_active=1 ORDER BY position")
	if err != nil {
		log.Printf("Error querying positions: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var p []string
	for rows.Next() {
		var s string
		rows.Scan(&s)
		p = append(p, s)
	}
	if p == nil {
		p = []string{}
	}
	json.NewEncoder(w).Encode(p)
}

// ═══════════════════════════════════════════════════════════════
// END OF SEGMENT 2
// Continue with SEGMENT 3 for Payments, Stats, Templates, Exports, Main
// ═══════════════════════════════════════════════════════════════// ═══════════════════════════════════════════════════════════════
// SECURE HR PAYROLL SYSTEM - SEGMENT 3 OF 3 (FINAL)
// Includes: Payments, Stats, Templates, Exports, Main Function
// APPEND THIS TO SEGMENT 2
// ═══════════════════════════════════════════════════════════════

// ================= PAYMENT MANAGEMENT =================

func getPayments(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	employeeIDStr := r.URL.Query().Get("employeeId")
	payPeriod := r.URL.Query().Get("payPeriod")
	query := "SELECT id, employee_id, employee_name, pay_period, base_salary, bonus, deductions, net_salary, generated_at, COALESCE(document_path, '') FROM payments WHERE 1=1"
	args := []interface{}{}
	if employeeIDStr != "" {
		empID, err := strconv.Atoi(employeeIDStr)
		if err != nil || empID < 1 {
			http.Error(w, "Invalid employee ID", http.StatusBadRequest)
			return
		}
		query += " AND employee_id = ?"
		args = append(args, employeeIDStr)
	}
	if payPeriod != "" {
		query += " AND pay_period = ?"
		args = append(args, payPeriod)
	}
	query += " ORDER BY generated_at DESC"
	rows, err := db.Query(query, args...)
	if err != nil {
		log.Printf("Error querying payments: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var payments []PaymentRecord
	for rows.Next() {
		var p PaymentRecord
		rows.Scan(&p.ID, &p.EmployeeID, &p.EmployeeName, &p.PayPeriod, &p.BaseSalary, &p.Bonus, &p.Deductions, &p.NetSalary, &p.GeneratedAt, &p.DocumentPath)
		payments = append(payments, p)
	}
	if payments == nil {
		payments = []PaymentRecord{}
	}
	json.NewEncoder(w).Encode(payments)
}

func addPaymentRecord(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	if r.Method != "POST" {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)
	var p PaymentRecord
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if p.EmployeeID < 1 {
		http.Error(w, "Invalid employee ID", http.StatusBadRequest)
		return
	}
	if p.BaseSalary < 0 || p.NetSalary < 0 {
		http.Error(w, "Invalid salary amounts", http.StatusBadRequest)
		return
	}
	if !validateString(p.PayPeriod, 6, 20) {
		http.Error(w, "Invalid pay period", http.StatusBadRequest)
		return
	}
	err := db.QueryRow("SELECT name FROM employees WHERE id=?", p.EmployeeID).Scan(&p.EmployeeName)
	if err != nil {
		http.Error(w, "Employee not found", http.StatusNotFound)
		return
	}
	p.GeneratedAt = time.Now().Format("2006-01-02 15:04:05")
	if p.NetSalary == 0 {
		p.NetSalary = p.BaseSalary + p.Bonus - p.Deductions
	}
	res, err := db.Exec("INSERT INTO payments (employee_id, employee_name, pay_period, base_salary, bonus, deductions, net_salary, generated_at, document_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		p.EmployeeID, p.EmployeeName, p.PayPeriod, p.BaseSalary, p.Bonus, p.Deductions, p.NetSalary, p.GeneratedAt, "")
	if err != nil {
		log.Printf("Error adding payment: %v", err)
		http.Error(w, "Failed to add payment", http.StatusInternalServerError)
		return
	}
	pid, _ := res.LastInsertId()
	p.ID = int(pid)
	userID := getUserID(r)
	auditLog(userID, "PAYMENT_ADDED", fmt.Sprintf("Payment ID: %d, Employee ID: %d, Amount: %.2f", p.ID, p.EmployeeID, p.NetSalary))
	json.NewEncoder(w).Encode(p)
}

func deletePayment(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	if r.Method != "DELETE" {
		return
	}
	idStr := r.URL.Query().Get("id")
	paymentID, err := strconv.Atoi(idStr)
	if err != nil || paymentID < 1 {
		http.Error(w, "Invalid payment ID", http.StatusBadRequest)
		return
	}
	var path string
	db.QueryRow("SELECT document_path FROM payments WHERE id=?", idStr).Scan(&path)
	if path != "" && validateFilename(path) {
		os.Remove(filepath.Join("generated", path))
	}
	db.Exec("DELETE FROM payments WHERE id=?", idStr)
	userID := getUserID(r)
	auditLog(userID, "PAYMENT_DELETED", fmt.Sprintf("Payment ID: %d", paymentID))
	w.WriteHeader(http.StatusOK)
}

func uploadPaymentDoc(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	if r.Method != "POST" {
		return
	}
	r.ParseMultipartForm(10 << 20)
	paymentID := r.FormValue("paymentId")
	if paymentID == "" {
		http.Error(w, "Payment ID required", http.StatusBadRequest)
		return
	}
	file, handler, err := r.FormFile("document")
	if err != nil {
		http.Error(w, "File error", http.StatusBadRequest)
		return
	}
	defer file.Close()
	if !strings.HasSuffix(handler.Filename, ".docx") {
		http.Error(w, "Only .docx files allowed", http.StatusBadRequest)
		return
	}
	if handler.Size > 10<<20 {
		http.Error(w, "File too large (max 10MB)", http.StatusBadRequest)
		return
	}
	os.MkdirAll("./generated", 0755)
	ext := filepath.Ext(handler.Filename)
	newFilename := fmt.Sprintf("ManualUpload_%s_%s%s", paymentID, time.Now().Format("20060102150405"), ext)
	dst, err := os.Create(filepath.Join("./generated", newFilename))
	if err != nil {
		log.Printf("Error creating file: %v", err)
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}
	defer dst.Close()
	io.Copy(dst, file)
	db.Exec("UPDATE payments SET document_path=? WHERE id=?", newFilename, paymentID)
	userID := getUserID(r)
	auditLog(userID, "DOCUMENT_UPLOADED", fmt.Sprintf("Payment ID: %s, File: %s", paymentID, newFilename))
	json.NewEncoder(w).Encode(map[string]string{"message": "Uploaded", "filename": newFilename})
}

func generatePayslips(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	if r.Method != "POST" {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)
	var req struct {
		EmployeeIDs []int   `json:"employeeIds"`
		PayPeriod   string  `json:"payPeriod"`
		Bonus       float64 `json:"bonus"`
		Deductions  float64 `json:"deductions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if len(req.EmployeeIDs) == 0 || len(req.EmployeeIDs) > 1000 {
		http.Error(w, "Invalid number of employees", http.StatusBadRequest)
		return
	}
	if !validateString(req.PayPeriod, 6, 20) {
		http.Error(w, "Invalid pay period format", http.StatusBadRequest)
		return
	}
	activeTemplate := getActiveTemplateName()
	templatePath := filepath.Join("templates", activeTemplate)
	if _, err := os.Stat(templatePath); os.IsNotExist(err) {
		http.Error(w, "Active template not found", http.StatusBadRequest)
		return
	}
	var results []PaymentRecord
	for _, empID := range req.EmployeeIDs {
		var empName, email, phone, addr, natID, position, dept, contractStart, contractEnd, excluded string
		var baseSalary float64
		var encName, encEmail, encPhone, encAddr, encNatID string
		err := db.QueryRow(`SELECT e.name, COALESCE(e.email, ''), COALESCE(e.phone, ''), COALESCE(e.address, ''), COALESCE(e.national_id, ''), COALESCE(e.excluded_months, ''),
                   c.position, c.department, c.base_salary, c.start_date, COALESCE(c.end_date, '')
            FROM employees e JOIN contracts c ON e.id = c.employee_id WHERE e.id=? AND c.is_active=1`, empID).Scan(&encName, &encEmail, &encPhone, &encAddr, &encNatID, &excluded, &position, &dept, &baseSalary, &contractStart, &contractEnd)
		if err != nil {
			continue
		}
		empName, _ = decrypt(encName)
		email, _ = decrypt(encEmail)
		phone, _ = decrypt(encPhone)
		addr, _ = decrypt(encAddr)
		natID, _ = decrypt(encNatID)
		if excluded != "" {
			excludedList := strings.Split(excluded, ",")
			parts := strings.Split(req.PayPeriod, "-")
			if len(parts) > 1 {
				targetMonth, _ := strconv.Atoi(parts[1])
				isExcluded := false
				for _, m := range excludedList {
					if m == strconv.Itoa(targetMonth) || m == req.PayPeriod {
						isExcluded = true
						break
					}
				}
				if isExcluded {
					continue
				}
			}
		}
		netSalary := baseSalary + req.Bonus - req.Deductions
		generatedAt := time.Now().Format("2006-01-02 15:04:05")
		cleanName := strings.ReplaceAll(empName, " ", "_")
		cleanPeriod := strings.ReplaceAll(req.PayPeriod, "-", "_")
		filename := fmt.Sprintf("Payslip_%s_%s.docx", cleanName, cleanPeriod)
		outputPath := filepath.Join("generated", filename)
		pyData := map[string]interface{}{
			"employee_name": empName, "employee_id": empID, "position": position, "department": dept,
			"email": email, "phone": phone, "address": addr, "national_id": natID,
			"base_salary": baseSalary, "bonus": req.Bonus, "deductions": req.Deductions, "net_salary": netSalary,
			"pay_period": req.PayPeriod, "contract_start": contractStart, "contract_end": contractEnd, "generated_date": generatedAt,
		}
		jsonData, _ := json.Marshal(pyData)
		tempJsonFile := filepath.Join("generated", fmt.Sprintf("temp_%d_%d.json", empID, time.Now().UnixNano()))
		if err := os.WriteFile(tempJsonFile, jsonData, 0644); err != nil {
			log.Printf("Error writing temp json: %v", err)
			continue
		}
		cmd := exec.Command("python3", filepath.Join("scripts", "generate_doc.py"), templatePath, outputPath, tempJsonFile)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			cmd = exec.Command("python", filepath.Join("scripts", "generate_doc.py"), templatePath, outputPath, tempJsonFile)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Run()
		}
		os.Remove(tempJsonFile)
		res, _ := db.Exec("INSERT INTO payments (employee_id, employee_name, pay_period, base_salary, bonus, deductions, net_salary, generated_at, document_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
			empID, empName, req.PayPeriod, baseSalary, req.Bonus, req.Deductions, netSalary, generatedAt, filename)
		pid, _ := res.LastInsertId()
		results = append(results, PaymentRecord{ID: int(pid), EmployeeName: empName, NetSalary: netSalary, DocumentPath: filename, PayPeriod: req.PayPeriod, BaseSalary: baseSalary})
	}
	userID := getUserID(r)
	auditLog(userID, "PAYSLIPS_GENERATED", fmt.Sprintf("Count: %d, Period: %s", len(results), req.PayPeriod))
	json.NewEncoder(w).Encode(results)
}

// ================= EMPLOYEE STATS =================

func getEmployeeStats(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	empIDStr := r.URL.Query().Get("id")
	empID, err := strconv.Atoi(empIDStr)
	if err != nil || empID < 1 {
		http.Error(w, "Invalid employee ID", http.StatusBadRequest)
		return
	}
	var excludedStr string
	err = db.QueryRow("SELECT COALESCE(excluded_months, '') FROM employees WHERE id=?", empID).Scan(&excludedStr)
	if err != nil {
		http.Error(w, "Employee not found", http.StatusNotFound)
		return
	}
	excludedList := strings.Split(excludedStr, ",")
	var contracts []Contract
	cRows, _ := db.Query("SELECT id, base_salary, start_date, COALESCE(end_date, ''), position FROM contracts WHERE employee_id=? ORDER BY start_date ASC", empID)
	for cRows.Next() {
		var c Contract
		cRows.Scan(&c.ID, &c.BaseSalary, &c.StartDate, &c.EndDate, &c.Position)
		contracts = append(contracts, c)
	}
	cRows.Close()
	if len(contracts) == 0 {
		json.NewEncoder(w).Encode(EmployeeStats{})
		return
	}
	paymentsMap := make(map[string]PaymentRecord)
	var latestPayment string
	pRows, _ := db.Query("SELECT id, pay_period, net_salary, document_path FROM payments WHERE employee_id=?", empID)
	for pRows.Next() {
		var p PaymentRecord
		pRows.Scan(&p.ID, &p.PayPeriod, &p.NetSalary, &p.DocumentPath)
		paymentsMap[p.PayPeriod] = p
		if p.PayPeriod > latestPayment {
			latestPayment = p.PayPeriod
		}
	}
	pRows.Close()
	firstStart, _ := time.Parse("2006-01-02", contracts[0].StartDate)
	today := time.Now()
	end := time.Date(today.Year(), today.Month(), 1, 0, 0, 0, 0, time.UTC)
	if latestPayment != "" {
		lp, _ := time.Parse("2006-01", latestPayment)
		if lp.After(end) {
			end = lp
		}
	}
	current := time.Date(firstStart.Year(), firstStart.Month(), 1, 0, 0, 0, 0, time.UTC)
	stats := EmployeeStats{Timeline: []TimelineItem{}}
	for !current.After(end) {
		period := current.Format("2006-01")
		monthGeneric := strconv.Itoa(int(current.Month()))
		var activeContract *Contract
		for _, c := range contracts {
			cStart, _ := time.Parse("2006-01-02", c.StartDate)
			cStartNorm := time.Date(cStart.Year(), cStart.Month(), 1, 0, 0, 0, 0, time.UTC)
			var cEndNorm time.Time
			if c.EndDate != "" {
				cEnd, _ := time.Parse("2006-01-02", c.EndDate)
				cEndNorm = time.Date(cEnd.Year(), cEnd.Month(), 1, 0, 0, 0, 0, time.UTC)
			} else {
				cEndNorm = time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)
			}
			if (current.Equal(cStartNorm) || current.After(cStartNorm)) && (current.Before(cEndNorm) || current.Equal(cEndNorm)) {
				temp := c
				activeContract = &temp
			}
		}
		if activeContract == nil {
			current = current.AddDate(0, 1, 0)
			continue
		}
		isExcluded := false
		for _, m := range excludedList {
			if m == monthGeneric || m == period {
				isExcluded = true
				break
			}
		}
		item := TimelineItem{Month: period, Position: activeContract.Position}
		if val, ok := paymentsMap[period]; ok {
			item.Status = "Paid"
			item.Amount = val.NetSalary
			item.PaymentID = val.ID
			item.DocPath = val.DocumentPath
			stats.TotalPaid += val.NetSalary
		} else {
			if isExcluded {
				item.Status = "Excluded"
				item.Amount = 0
			} else {
				if current.After(time.Date(today.Year(), today.Month(), 1, 0, 0, 0, 0, time.UTC)) {
					item.Status = "Future"
				} else {
					item.Status = "Unpaid"
					stats.PastUnpaid += activeContract.BaseSalary
				}
				item.Amount = activeContract.BaseSalary
			}
		}
		if !isExcluded {
			stats.TotalContractValue += activeContract.BaseSalary
		}
		stats.Timeline = append(stats.Timeline, item)
		current = current.AddDate(0, 1, 0)
	}
	stats.ToBePaid = stats.PastUnpaid
	for i, j := 0, len(stats.Timeline)-1; i < j; i, j = i+1, j-1 {
		stats.Timeline[i], stats.Timeline[j] = stats.Timeline[j], stats.Timeline[i]
	}
	json.NewEncoder(w).Encode(stats)
}

// ================= TEMPLATES =================

func getTemplates(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	files, err := os.ReadDir("./templates")
	if err != nil {
		log.Printf("Error reading templates: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	var templates []TemplateFile
	active := getActiveTemplateName()
	fileInfos := make([]os.FileInfo, 0, len(files))
	for _, entry := range files {
		info, _ := entry.Info()
		fileInfos = append(fileInfos, info)
	}
	sort.Slice(fileInfos, func(i, j int) bool { return fileInfos[i].ModTime().After(fileInfos[j].ModTime()) })
	for _, info := range fileInfos {
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".docx") && info.Name() != "active_template.docx" {
			templates = append(templates, TemplateFile{Name: info.Name(), IsActive: info.Name() == active, UpdatedAt: info.ModTime().Format("2006-01-02 15:04")})
		}
	}
	if templates == nil {
		templates = []TemplateFile{}
	}
	json.NewEncoder(w).Encode(templates)
}

func uploadTemplate(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	if r.Method != "POST" {
		return
	}
	r.ParseMultipartForm(10 << 20)
	file, handler, err := r.FormFile("template")
	if err != nil {
		http.Error(w, "File error", http.StatusBadRequest)
		return
	}
	defer file.Close()
	if !validateFilename(handler.Filename) {
		http.Error(w, "Invalid filename", http.StatusBadRequest)
		return
	}
	if handler.Size > 10<<20 {
		http.Error(w, "File too large (max 10MB)", http.StatusBadRequest)
		return
	}
	os.MkdirAll("./templates", 0755)
	dst, err := os.Create(filepath.Join("./templates", handler.Filename))
	if err != nil {
		log.Printf("Error creating template file: %v", err)
		http.Error(w, "Failed to save template", http.StatusInternalServerError)
		return
	}
	defer dst.Close()
	io.Copy(dst, file)
	if _, err := os.Stat("templates/active_template.docx"); os.IsNotExist(err) {
		copyFile(filepath.Join("templates", handler.Filename), "templates/active_template.docx")
	}
	userID := getUserID(r)
	auditLog(userID, "TEMPLATE_UPLOADED", fmt.Sprintf("File: %s", handler.Filename))
	json.NewEncoder(w).Encode(map[string]string{"message": "Uploaded"})
}

func setActiveTemplate(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)
	var req struct {
		Filename string `json:"filename"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if !validateFilename(req.Filename) {
		http.Error(w, "Invalid filename", http.StatusBadRequest)
		return
	}
	sourcePath := filepath.Join("templates", req.Filename)
	if _, err := os.Stat(sourcePath); os.IsNotExist(err) {
		http.Error(w, "Template not found", http.StatusNotFound)
		return
	}
	copyFile(sourcePath, "templates/active_template.docx")
	userID := getUserID(r)
	auditLog(userID, "TEMPLATE_ACTIVATED", fmt.Sprintf("File: %s", req.Filename))
	json.NewEncoder(w).Encode(map[string]string{"message": "Activated"})
}

func deleteTemplate(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	filename := r.URL.Query().Get("filename")
	if !validateFilename(filename) {
		http.Error(w, "Invalid filename", http.StatusBadRequest)
		return
	}
	if filename == "active_template.docx" {
		http.Error(w, "Cannot delete active template", http.StatusForbidden)
		return
	}
	filePath := filepath.Join("templates", filename)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		http.Error(w, "Template not found", http.StatusNotFound)
		return
	}
	os.Remove(filePath)
	userID := getUserID(r)
	auditLog(userID, "TEMPLATE_DELETED", fmt.Sprintf("File: %s", filename))
	w.WriteHeader(http.StatusOK)
}

func getActiveTemplateName() string {
	if _, err := os.Stat("templates/active_template.docx"); err == nil {
		return "active_template.docx"
	}
	return "template.docx"
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// ================= EXPORTS WITH DECRYPTION =================

func exportAllData(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	userID := getUserID(r)
	auditLog(userID, "EXPORT_ALL_STARTED", fmt.Sprintf("IP: %s", r.RemoteAddr))
	query := `SELECT e.id, e.name, c.department, c.position, c.base_salary, 
               COALESCE(p.pay_period, 'N/A'), COALESCE(p.net_salary, 0), 
               COALESCE(p.bonus, 0), COALESCE(p.deductions, 0), COALESCE(p.generated_at, '') 
        FROM employees e 
        JOIN contracts c ON e.id = c.employee_id AND c.is_active=1
        LEFT JOIN payments p ON e.id = p.employee_id 
        ORDER BY c.department, e.name, p.pay_period`
	rows, err := db.Query(query)
	if err != nil {
		log.Printf("Error exporting data: %v", err)
		auditLog(userID, "EXPORT_ALL_FAILED", fmt.Sprintf("Error: %v", err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	csv := "Employee ID,Name,Department,Position,Base Salary,Pay Period,Net Salary,Bonus,Deductions,Generated Date\n"
	exportedCount := 0
	for rows.Next() {
		var id int
		var encName, dept, pos, period, genDate string
		var base, net, bonus, ded float64
		rows.Scan(&id, &encName, &dept, &pos, &base, &period, &net, &bonus, &ded, &genDate)
		name, err := decrypt(encName)
		if err != nil {
			log.Printf("⚠️  Failed to decrypt employee %d: %v", id, err)
			name = "[DECRYPTION ERROR]"
		}
		csv += fmt.Sprintf("%d,\"%s\",\"%s\",\"%s\",%.3f,\"%s\",%.3f,%.3f,%.3f,\"%s\"\n",
			id, name, dept, pos, base, period, net, bonus, ded, genDate)
		exportedCount++
	}
	auditLog(userID, "EXPORT_ALL_SUCCESS", fmt.Sprintf("Exported %d records", exportedCount))
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("Full_Database_Export_%s.csv", timestamp)
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Write([]byte(csv))
}

func exportDepartment(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	department := r.URL.Query().Get("department")
	if department == "" {
		http.Error(w, "Department required", http.StatusBadRequest)
		return
	}
	department = sanitizeInput(department)
	if !validateString(department, 1, 100) {
		http.Error(w, "Invalid department name", http.StatusBadRequest)
		return
	}
	userID := getUserID(r)
	auditLog(userID, "EXPORT_DEPARTMENT_STARTED", fmt.Sprintf("Department: %s", department))
	rows, err := db.Query("SELECT e.id, e.name, e.email FROM employees e JOIN contracts c ON e.id=c.employee_id WHERE c.department=? AND c.is_active=1", department)
	if err != nil {
		log.Printf("Error exporting department: %v", err)
		auditLog(userID, "EXPORT_DEPARTMENT_FAILED", fmt.Sprintf("Department: %s, Error: %v", department, err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	csv := "ID,Name,Email\n"
	exportedCount := 0
	for rows.Next() {
		var id int
		var encName, encEmail sql.NullString
		rows.Scan(&id, &encName, &encEmail)
		name, err1 := decrypt(encName.String)
		email, err2 := decrypt(encEmail.String)
		if err1 != nil {
			log.Printf("⚠️  Failed to decrypt name for employee %d", id)
			name = "[DECRYPTION ERROR]"
		}
		if err2 != nil && encEmail.Valid {
			email = "[DECRYPTION ERROR]"
		}
		csv += fmt.Sprintf("%d,%s,%s\n", id, name, email)
		exportedCount++
	}
	auditLog(userID, "EXPORT_DEPARTMENT_SUCCESS", fmt.Sprintf("Department: %s, Count: %d", department, exportedCount))
	timestamp := time.Now().Format("20060102_150405")
	safeDept := strings.ReplaceAll(department, " ", "_")
	filename := fmt.Sprintf("Department_%s_%s.csv", safeDept, timestamp)
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Write([]byte(csv))
}

// ================= MAIN FUNCTION =================

func main() {
	if err := initEncryptionKey(); err != nil {
		log.Fatal("❌ Failed to initialize encryption:", err)
	}
	if err := initDB(); err != nil {
		log.Fatal("❌ Failed to initialize database:", err)
	}
	defer db.Close()

	os.MkdirAll("./static", 0755)
	os.MkdirAll("./templates", 0755)
	os.MkdirAll("./generated", 0755)

	http.HandleFunc("/api/login", rateLimitMiddleware(login))
	http.HandleFunc("/api/check-setup", checkSystemSetup)
	http.HandleFunc("/api/register-owner", registerUser)
	http.HandleFunc("/api/verify-2fa", rateLimitMiddleware(verify2FALogin))
	http.HandleFunc("/api/auth-status", checkAuthStatus)
	http.HandleFunc("/api/logout", logout)
	http.HandleFunc("/api/user/change-password", authMiddleware(changePassword))
	http.HandleFunc("/api/user/delete-account", authMiddleware(deleteAccount))
	http.HandleFunc("/api/users/add", authMiddleware(createUser))
	http.HandleFunc("/api/employees", authMiddleware(getEmployees))
	http.HandleFunc("/api/employees/add", authMiddleware(addEmployee))
	http.HandleFunc("/api/employees/update", authMiddleware(updateEmployee))
	http.HandleFunc("/api/employees/delete", authMiddleware(deleteEmployee))
	http.HandleFunc("/api/employees/renew-contract", authMiddleware(renewContract))
	http.HandleFunc("/api/employees/exclude-bulk", authMiddleware(bulkExcludeMonths))
	http.HandleFunc("/api/departments", authMiddleware(getDepartments))
	http.HandleFunc("/api/positions", authMiddleware(getPositions))
	http.HandleFunc("/api/payments", authMiddleware(getPayments))
	http.HandleFunc("/api/payments/add", authMiddleware(addPaymentRecord))
	http.HandleFunc("/api/payments/delete", authMiddleware(deletePayment))
	http.HandleFunc("/api/payments/upload-doc", authMiddleware(uploadPaymentDoc))
	http.HandleFunc("/api/generate-payslips", authMiddleware(generatePayslips))
	http.HandleFunc("/api/employee/stats", authMiddleware(getEmployeeStats))
	http.HandleFunc("/api/templates", authMiddleware(getTemplates))
	http.HandleFunc("/api/template/upload", authMiddleware(uploadTemplate))
	http.HandleFunc("/api/template/activate", authMiddleware(setActiveTemplate))
	http.HandleFunc("/api/template/delete", authMiddleware(deleteTemplate))
	http.HandleFunc("/api/template/info", authMiddleware(getTemplates))
	http.HandleFunc("/api/export/department", authMiddleware(exportDepartment))
	http.HandleFunc("/api/export/all", authMiddleware(exportAllData))
	http.HandleFunc("/api/2fa/generate", authMiddleware(generate2FA))
	http.HandleFunc("/api/2fa/enable", authMiddleware(enable2FA))

	fs := http.FileServer(http.Dir("./static"))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login.html" || r.URL.Path == "/register.html" ||
			r.URL.Path == "/login.js" || r.URL.Path == "/register.js" ||
			strings.HasSuffix(r.URL.Path, ".css") ||
			strings.HasSuffix(r.URL.Path, ".js") ||
			strings.HasSuffix(r.URL.Path, ".png") {
			fs.ServeHTTP(w, r)
			return
		}
		c, err := r.Cookie("session_token")
		authorized := false
		if err == nil {
			sessionMutex.RLock()
			_, authorized = sessions[c.Value]
			sessionMutex.RUnlock()
		}
		if !authorized {
			http.Redirect(w, r, "/login.html", http.StatusFound)
			return
		}
		fs.ServeHTTP(w, r)
	})

	http.Handle("/generated/", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		http.StripPrefix("/generated/", http.FileServer(http.Dir("./generated"))).ServeHTTP(w, r)
	}))

	log.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	log.Println("🔒 SECURE HR PAYROLL SYSTEM STARTING")
	log.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	if os.Getenv("PRODUCTION") == "true" {
		log.Println("🟢 PRODUCTION MODE: HTTPS Enabled")
		log.Println("📡 Server: https://localhost:8443")
		log.Println("⚠️  Ensure valid TLS certificates are in ./certs/")
		log.Fatal(http.ListenAndServeTLS(":8443", "./certs/server.crt", "./certs/server.key", nil))
	} else {
		log.Println("🟡 DEVELOPMENT MODE: HTTP (INSECURE)")
		log.Println("📡 Server: http://localhost:8080")
		log.Println("⚠️  WARNING: Deploy behind HTTPS reverse proxy for production!")
		log.Println("⚠️  Recommended: Use Caddy or nginx with Let's Encrypt")
		log.Fatal(http.ListenAndServe(":8080", nil))
	}
}

// ═══════════════════════════════════════════════════════════════
// END OF SEGMENT 3 - COMPLETE SECURE MAIN.GO
//
// TO CREATE FULL FILE:
// cat main_SEGMENT_1.go main_SEGMENT_2.go main_SEGMENT_3.go > main.go
//
// OR use the combine script provided
// ═══════════════════════════════════════════════════════════════