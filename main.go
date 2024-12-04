package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/duo-labs/webauthn/webauthn"
)

// User represents a user in our system.
type User struct {
	ID          uint64
	Name        string
	DisplayName string
	Credentials []webauthn.Credential
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

func main() {
	var err error
	webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "Global Wallet",
		RPID:          "localhost", // TODO: Change this to your domain.
		RPOrigin:      "http://localhost:8080",
	})

	if err != nil {
		log.Fatal(err)
	}

	// Set up routes.
	http.HandleFunc("/register/begin", BeginRegistration)
	http.HandleFunc("/register/finish", FinishRegistration)
	http.HandleFunc("/login/begin", BeginLogin)
	http.HandleFunc("/login/finish", FinishLogin)

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

// Helper function to write JSON responses
func writeError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// BeginRegistration handles the registration initiation.
func BeginRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var req RegistrationBeginRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		writeError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	username := req.Username
	displayName := req.DisplayName

	if username == "" || displayName == "" {
		writeError(w, "Username and display name required", http.StatusBadRequest)
		return
	}

	user := getUser(username)
	if user == nil {
		user = createUser(username, displayName)
	}

	options, sessionData, err := webAuthn.BeginRegistration(user)
	if err != nil {
		writeError(w, "Failed to begin registration", http.StatusInternalServerError)
		return
	}

	registrationSessions[username] = sessionData

	WriteJSON(w, options)
}

// FinishRegistration completes the registration.
func FinishRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var req RegistrationFinishRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		writeError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	username := req.Username
	attestationResponse := req.AttestationResponse

	if username == "" || attestationResponse == nil {
		writeError(w, "Username and attestationResponse required", http.StatusBadRequest)
		return
	}

	user := getUser(username)
	if user == nil {
		writeError(w, "User not found", http.StatusBadRequest)
		return
	}

	sessionData, ok := registrationSessions[username]
	if !ok {
		writeError(w, "No registration session data found", http.StatusBadRequest)
		return
	}

	r.Body = ioutil.NopCloser(bytes.NewReader(attestationResponse))
	r.Header.Set("Content-Type", "application/json")

	credential, err := webAuthn.FinishRegistration(user, *sessionData, r)
	if err != nil {
		writeError(w, "Failed to finish registration: "+err.Error(), http.StatusBadRequest)
		return
	}

	user.Credentials = append(user.Credentials, *credential)

	delete(registrationSessions, username)

	WriteJSON(w, map[string]string{"status": "ok"})
}

// BeginLogin initiates the login process.
func BeginLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var req LoginBeginRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		writeError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	username := req.Username

	if username == "" {
		writeError(w, "Username required", http.StatusBadRequest)
		return
	}

	user := getUser(username)
	if user == nil {
		writeError(w, "User not found", http.StatusBadRequest)
		return
	}

	options, sessionData, err := webAuthn.BeginLogin(user)
	if err != nil {
		writeError(w, "Failed to begin login", http.StatusInternalServerError)
		return
	}

	loginSessions[username] = sessionData

	WriteJSON(w, options)
}

// FinishLogin completes the login process.
func FinishLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var req LoginFinishRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		writeError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	username := req.Username
	assertionResponse := req.AssertionResponse

	if username == "" || assertionResponse == nil {
		writeError(w, "Username and assertionResponse required", http.StatusBadRequest)
		return
	}

	user := getUser(username)
	if user == nil {
		writeError(w, "User not found", http.StatusBadRequest)
		return
	}

	sessionData, ok := loginSessions[username]
	if !ok {
		writeError(w, "No login session data found", http.StatusBadRequest)
		return
	}

	r.Body = ioutil.NopCloser(bytes.NewReader(assertionResponse))
	r.Header.Set("Content-Type", "application/json")

	_, err = webAuthn.FinishLogin(user, *sessionData, r)
	if err != nil {
		writeError(w, "Failed to finish login: "+err.Error(), http.StatusBadRequest)
		return
	}

	delete(loginSessions, username)

	WriteJSON(w, map[string]string{"status": "ok"})
}

// WriteJSON writes data as JSON to the response.
func WriteJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		writeError(w, "Failed to write JSON response", http.StatusInternalServerError)
	}
}
