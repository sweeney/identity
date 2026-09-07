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

	// A generated password exists in exactly two places: this variable and the
	// file. Persist it BEFORE creating the account — if the write fails after
	// the user exists, the only admin has a password nobody has ever seen, and
	// the only way back in is --reset-admin.
	if generated {
		if writeErr := writeInitialPassword(username, password); writeErr != nil {
			return writeErr
		}
	}

	_, err = svc.Create(username, username, password, domain.RoleAdmin)
	if err != nil {
		if generated {
			// The account was not created, so the file describes nothing.
			os.Remove(initialPasswordFile)
		}
		return fmt.Errorf("seed admin user: %w", err)
	}

	if generated {
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

// writeInitialPassword writes the generated credentials with owner-only
// permissions.
//
// os.WriteFile would not do: it applies its permission argument only when it
// creates the file, so a leftover file with looser permissions keeps them, and
// it follows a symlink at that path. Removing any existing entry first and
// creating with O_EXCL means the mode is always ours and a symlink is replaced
// rather than written through.
func writeInitialPassword(username, password string) error {
	// Lstat, not Stat: a symlink here must be seen as a symlink and replaced,
	// never followed. Anything that is not a regular file or symlink is not
	// something we put there, so refuse rather than delete it.
	switch info, err := os.Lstat(initialPasswordFile); {
	case err == nil && (info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0):
		if rmErr := os.Remove(initialPasswordFile); rmErr != nil {
			return fmt.Errorf("clear stale %s: %w", initialPasswordFile, rmErr)
		}
	case err == nil:
		return fmt.Errorf("cannot write %s: path exists and is not a regular file (mode %s)",
			initialPasswordFile, info.Mode())
	case !os.IsNotExist(err):
		return fmt.Errorf("stat %s: %w", initialPasswordFile, err)
	}

	f, err := os.OpenFile(initialPasswordFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("write %s: %w", initialPasswordFile, err)
	}
	defer f.Close()

	if _, err := fmt.Fprintf(f, "Username: %s\nPassword: %s\n", username, password); err != nil {
		return fmt.Errorf("write %s: %w", initialPasswordFile, err)
	}
	return f.Close()
}

func generatePassword() (string, error) {
	buf := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
