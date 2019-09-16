package envtypes

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
)

// KeyGenerator defines the key generator to use
type KeyGenerator func() (crypto.PrivateKey, error)

// UnmarshalText implements encoding.TextUnmarshaler for KeyGenerator
func (k *KeyGenerator) UnmarshalText(in []byte) error {
	switch strings.ToLower(string(in)) {
	case "ec", "ecdsa":
		*k = func() (crypto.PrivateKey, error) {
			return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		}
	case "rsa":
		*k = func() (crypto.PrivateKey, error) {
			return rsa.GenerateKey(rand.Reader, 2048)
		}
	default:
		return errors.New(`invalid key generator specified, supported key generators are "ecdsa" and "rsa"`)
	}
	return nil
}

// Generate implements certify.KeyGenerator for KeyGenerator
func (k KeyGenerator) Generate() (crypto.PrivateKey, error) {
	return k()
}
