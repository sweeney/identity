package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/service"
)

const initialPasswordFile = "initial-password.txt"

// seedIfEmpty creates an initial admin user if no users exist yet.
//
// Three modes:
//  1. ADMIN_USERNAME + ADMIN_PASSWORD env vars set → create admin with those creds (unattended)
//  2. Env vars not set → generate a random password, write it to initial-password.txt (0600)
//  3. Users already exist → no-op (and clean up any leftover initial-password.txt)
func seedIfEmpty(svc *service.UserService, username, password string) error {
	users, err := svc.List()
	if err != nil {
		return fmt.Errorf("seed check: %w", err)
	}
	if len(users) > 0 {
		// Clean up password file from a previous first run, if it exists.
		os.Remove(initialPasswordFile)
		return nil
	}

	// No users — first run. Determine credentials.
	if username == "" {
		username = "admin"
	}

	generated := false
	if password == "" {
		password, err = generatePassword()
		if err != nil {
			return fmt.Errorf("generate password: %w", err)
		}
		generated = true
	}

	_, err = svc.Create(username, username, password, domain.RoleAdmin)
	if err != nil {
		return fmt.Errorf("seed admin user: %w", err)
	}

	if generated {
		content := fmt.Sprintf("Username: %s\nPassword: %s\n", username, password)
		if writeErr := os.WriteFile(initialPasswordFile, []byte(content), 0600); writeErr != nil {
			return fmt.Errorf("write %s: %w", initialPasswordFile, writeErr)
		}
		log.Println("════════════════════════════════════════════════════")
		log.Println("  FIRST RUN — admin account created")
		log.Printf("  Credentials written to %s", initialPasswordFile)
		log.Println("  Read it, then delete the file.")
		log.Println("  Change the password after login at /admin/users")
		log.Println("════════════════════════════════════════════════════")
	} else {
		log.Printf("first run: created admin user %q from environment", username)
	}

	return nil
}

func generatePassword() (string, error) {
	buf := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
