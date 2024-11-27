package main

import (
	"encoding/json"
	"fmt"
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
var user *User

var registrationSessionData *webauthn.SessionData
var loginSessionData *webauthn.SessionData

func main() {
	var err error
	webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "Simple Go WebAuthn App",
		RPID:          "localhost", // TODO: Change this to your domain.
		RPOrigin:      "http://localhost:8080",
	})

	if err != nil {
		log.Fatal(err)
	}

	// Initialize a user.
	user = &User{
		ID:          1,
		Name:        "username",
		DisplayName: "User Display Name",
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

// BeginRegistration handles the registration initiation.
func BeginRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	options, sessionData, err := webAuthn.BeginRegistration(user)
	if err != nil {
		http.Error(w, "Failed to begin registration", http.StatusInternalServerError)
		return
	}

	// Save the session data.
	registrationSessionData = sessionData

	WriteJSON(w, options)
}

// FinishRegistration completes the registration.
func FinishRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	credential, err := webAuthn.FinishRegistration(user, *registrationSessionData, r)
	if err != nil {
		http.Error(w, "Failed to finish registration: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Save the credential to the user.
	user.Credentials = append(user.Credentials, *credential)

	WriteJSON(w, map[string]string{"status": "ok"})
}

// BeginLogin initiates the login process.
func BeginLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	options, sessionData, err := webAuthn.BeginLogin(user)
	if err != nil {
		http.Error(w, "Failed to begin login", http.StatusInternalServerError)
		return
	}

	// Save the session data.
	loginSessionData = sessionData

	WriteJSON(w, options)
}

// FinishLogin completes the login process.
func FinishLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	_, err := webAuthn.FinishLogin(user, *loginSessionData, r)
	if err != nil {
		http.Error(w, "Failed to finish login: "+err.Error(), http.StatusBadRequest)
		return
	}

	WriteJSON(w, map[string]string{"status": "ok"})
}

// WriteJSON writes data as JSON to the response.
func WriteJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		http.Error(w, "Failed to write JSON response", http.StatusInternalServerError)
	}
}
