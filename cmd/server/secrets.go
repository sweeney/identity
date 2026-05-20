package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/sweeney/identity/common/secrets"
	"github.com/sweeney/identity/internal/db"
)

// serverSecrets is an alias so existing callers in this package compile unchanged.
type serverSecrets = secrets.Secrets

func resolveServerSecrets(database *db.Database) (*serverSecrets, error) {
	return secrets.Resolve(database)
}

func rotateJWTSecret(database *db.Database) error {
	return secrets.RotateJWT(database)
}

func clearPrevJWTSecret(database *db.Database) error {
	return secrets.ClearPrevJWT(database)
}

// encodeECKey and parseECKey are kept here for use by secrets_test.go.

func encodeECKey(key *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", err
	}
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	return string(pem.EncodeToMemory(block)), nil
}

func parseECKey(pemStr string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}
