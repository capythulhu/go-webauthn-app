package main

import (
	"bytes"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"net/http"
	"strconv"
	"time"

	"github.com/duo-labs/webauthn/webauthn"
)

// User represents a user in our system.
type User struct {
	ID          uint64
	Name        string
	DisplayName string
	Credentials []webauthn.Credential
	N           int
}

// Implement webauthn.User interface methods.
func (u *User) WebAuthnID() []byte {
	return []byte(fmt.Sprintf("%d", u.ID))
}

func (u *User) WebAuthnName() string {
	return u.Name
}

func (u *User) WebAuthnDisplayName() string {
	return u.DisplayName
}

func (u *User) WebAuthnIcon() string {
	return ""
}

func (u *User) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

var webAuthn *webauthn.WebAuthn

// Map to store users
var users = map[string]*User{}
var userIDCounter uint64 = 1

var registrationSessions = map[string]*webauthn.SessionData{}
var loginSessions = map[string]*webauthn.SessionData{}

// Map to store session private keys
var sessionPrivateKeys = map[string]*rsa.PrivateKey{}

func main() {
	var err error
	webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "Simple Global Wallet",
		RPID:          "localhost", // TODO: Change this to your domain.
		RPOrigin:      "http://localhost:8080",
	})

	if err != nil {
		log.Fatal(err)
	}

	mrand.Seed(time.Now().UnixNano())

	// Set up routes.
	http.HandleFunc("/register/begin", BeginRegistration)
	http.HandleFunc("/register/finish", FinishRegistration)
	http.HandleFunc("/login/begin", BeginLogin)
	http.HandleFunc("/login/finish", FinishLogin)
	http.HandleFunc("/compute", ComputeHandler)

	// Serve static files.
	http.Handle("/", http.FileServer(http.Dir("./static")))

	log.Println("Starting server on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// Request structs
type RegistrationBeginRequest struct {
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
}

type RegistrationFinishRequest struct {
	Username            string          `json:"username"`
	AttestationResponse json.RawMessage `json:"attestationResponse"`
}

type LoginBeginRequest struct {
	Username string `json:"username"`
}

type LoginFinishRequest struct {
	Username          string          `json:"username"`
	AssertionResponse json.RawMessage `json:"assertionResponse"`
}

// Helper functions to manage users
func getUser(username string) *User {
	user, ok := users[username]
	if !ok {
		return nil
	}
	return user
}

func createUser(username string, displayName string) *User {
	userIDCounter++
	user := &User{
		ID:          userIDCounter,
		Name:        username,
		DisplayName: displayName,
	}
	users[username] = user
	return user
}

// WriteError writes an error message as JSON to the response.
func WriteError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// BeginRegistration handles the registration initiation.
func BeginRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		WriteError(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var req RegistrationBeginRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		WriteError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	username := req.Username
	displayName := req.DisplayName

	if username == "" || displayName == "" {
		WriteError(w, "Username and display name required", http.StatusBadRequest)
		return
	}

	user := getUser(username)
	if user == nil {
		user = createUser(username, displayName)
	}

	options, sessionData, err := webAuthn.BeginRegistration(user)
	if err != nil {
		WriteError(w, "Failed to begin registration", http.StatusInternalServerError)
		return
	}

	registrationSessions[username] = sessionData

	fmt.Println("Registration begin succeeded for", username)
	WriteJSON(w, options)
}

// FinishRegistration completes the registration.
func FinishRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		WriteError(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var req RegistrationFinishRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		WriteError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	username := req.Username
	attestationResponse := req.AttestationResponse

	if username == "" || attestationResponse == nil {
		WriteError(w, "Username and attestationResponse required", http.StatusBadRequest)
		return
	}

	user := getUser(username)
	if user == nil {
		WriteError(w, "User not found", http.StatusBadRequest)
		return
	}

	sessionData, ok := registrationSessions[username]
	if !ok {
		WriteError(w, "No registration session data found", http.StatusBadRequest)
		return
	}

	r.Body = io.NopCloser(bytes.NewReader(attestationResponse))
	r.Header.Set("Content-Type", "application/json")

	credential, err := webAuthn.FinishRegistration(user, *sessionData, r)
	if err != nil {
		WriteError(w, "Failed to finish registration: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Save the credential to the user.
	user.Credentials = append(user.Credentials, *credential)

	// Generate N and store it in the user record
	user.N = mrand.Intn(1000) // Random number between 0 and 999

	delete(registrationSessions, username)

	fmt.Println("Registration finish succeeded for", username, "with N =", user.N)
	WriteJSON(w, map[string]string{"status": "ok"})
}

// BeginLogin initiates the login process.
func BeginLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		WriteError(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var req LoginBeginRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		WriteError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	username := req.Username

	if username == "" {
		WriteError(w, "Username required", http.StatusBadRequest)
		return
	}

	user := getUser(username)
	if user == nil {
		WriteError(w, "User not found", http.StatusBadRequest)
		return
	}

	options, sessionData, err := webAuthn.BeginLogin(user)
	if err != nil {
		WriteError(w, "Failed to begin login", http.StatusInternalServerError)
		return
	}

	loginSessions[username] = sessionData

	fmt.Println("Login begin succeeded for", username)
	WriteJSON(w, options)
}

// FinishLogin completes the login process.
func FinishLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		WriteError(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var req LoginFinishRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		WriteError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	username := req.Username
	assertionResponse := req.AssertionResponse

	if username == "" || assertionResponse == nil {
		WriteError(w, "Username and assertionResponse required", http.StatusBadRequest)
		return
	}

	user := getUser(username)
	if user == nil {
		WriteError(w, "User not found", http.StatusBadRequest)
		return
	}

	sessionData, ok := loginSessions[username]
	if !ok {
		WriteError(w, "No login session data found", http.StatusBadRequest)
		return
	}

	r.Body = io.NopCloser(bytes.NewReader(assertionResponse))
	r.Header.Set("Content-Type", "application/json")

	_, err = webAuthn.FinishLogin(user, *sessionData, r)
	if err != nil {
		WriteError(w, "Failed to finish login: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		WriteError(w, "Failed to generate key pair", http.StatusInternalServerError)
		return
	}
	publicKey := &privateKey.PublicKey

	// Store private key in sessions map
	sessionPrivateKeys[username] = privateKey

	// Marshal the public key to PKIX, ASN.1 DER form
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		WriteError(w, "Failed to marshal public key", http.StatusInternalServerError)
		return
	}

	// Base64 encode the public key
	pubKeyBase64 := base64.StdEncoding.EncodeToString(pubKeyBytes)

	delete(loginSessions, username)

	fmt.Println("Login finish succeeded for", username)
	// Send public key to client
	WriteJSON(w, map[string]string{
		"status":    "ok",
		"publicKey": pubKeyBase64,
	})
}

// ComputeHandler handles the computation of N + M.
func ComputeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		WriteError(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username   string `json:"username"`
		MEncrypted string `json:"m_encrypted"`
	}

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		WriteError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	username := req.Username
	mEncryptedBase64 := req.MEncrypted

	if username == "" || mEncryptedBase64 == "" {
		WriteError(w, "Username and m_encrypted required", http.StatusBadRequest)
		return
	}

	// Get user
	user := getUser(username)
	if user == nil {
		WriteError(w, "User not found", http.StatusBadRequest)
		return
	}

	// Get private key from session
	privateKey, ok := sessionPrivateKeys[username]
	if !ok {
		WriteError(w, "No session found for user", http.StatusBadRequest)
		return
	}

	// Decode m_encrypted from base64
	mEncryptedBytes, err := base64.RawURLEncoding.DecodeString(mEncryptedBase64)
	if err != nil {
		WriteError(w, "Failed to decode m_encrypted", http.StatusBadRequest)
		return
	}

	// Decrypt M
	mDecryptedBytes, err := rsa.DecryptOAEP(sha256.New(), crand.Reader, privateKey, mEncryptedBytes, nil)
	if err != nil {
		WriteError(w, "Failed to decrypt m_encrypted", http.StatusBadRequest)
		return
	}

	// Convert M to integer
	mStr := string(mDecryptedBytes)
	mInt, err := strconv.Atoi(mStr)
	if err != nil {
		WriteError(w, "Invalid M value", http.StatusBadRequest)
		return
	}

	// Compute N + M
	nPlusM := user.N + mInt

	fmt.Println("Computed N + M for", username)
	WriteJSON(w, map[string]int{"n_plus_m": nPlusM})
}

// WriteJSON writes data as JSON to the response.
func WriteJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		http.Error(w, "Failed to write JSON response", http.StatusInternalServerError)
	}
}
