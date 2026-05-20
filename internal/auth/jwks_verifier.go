package auth

import commonauth "github.com/sweeney/identity/common/auth"

// JWKSVerifierConfig is an alias for the common auth JWKSVerifierConfig.
// Callers importing internal/auth do not need a second import.
type JWKSVerifierConfig = commonauth.JWKSVerifierConfig

// JWKSVerifier is an alias for the common auth JWKSVerifier.
type JWKSVerifier = commonauth.JWKSVerifier

// NewJWKSVerifier constructs a JWKSVerifier. Delegates to common/auth.
var NewJWKSVerifier = commonauth.NewJWKSVerifier
