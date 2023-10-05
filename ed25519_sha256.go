package neared25519sha256

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/kwilteam/kwil-db/pkg/auth"   // to register, but we could reverse this and have the stub in kwil-db do it
	"github.com/kwilteam/kwil-db/pkg/crypto" // for error types
)

func init() {
	err := auth.RegisterAuthenticator(ed25519Sha256Auth, Ed22519Sha256Authenticator{})
	if err != nil {
		panic(err)
	}
}

const (
	// ed25519Sha256Auth is the authenticator name
	// the "nr" suffix is for NEAR, and provides backwards compatibility
	ed25519Sha256Auth = "ed25519_nr_jc"
)

// Ed22519Sha256Authenticator is an authenticator that applies the sha256 hash
// to the message before signing, and it generates Near addresses.
type Ed22519Sha256Authenticator struct{}

var _ auth.Authenticator = Ed22519Sha256Authenticator{}

// Address generates a NEAR implicit address from a public key
func (e Ed22519Sha256Authenticator) Address(publicKey []byte) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("invalid ed25519 public key size for generating near address: %d", len(publicKey))
	}

	return hex.EncodeToString(publicKey), nil
}

func verifySignature(pub, msg, sig []byte) error {
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("ed25519: %w: expected: %d, got: %d", crypto.ErrInvalidSignatureLength,
			ed25519.SignatureSize, len(sig))
	}

	ok := ed25519.Verify(pub, msg, sig)
	if !ok {
		return crypto.ErrInvalidSignature
	}
	return nil
}

// Verify verifies the signature against the given public key and data.
func (e Ed22519Sha256Authenticator) Verify(publicKey, msg, signature []byte) error {
	hash := sha256.Sum256(msg)
	return verifySignature(publicKey, hash[:], signature)
}
