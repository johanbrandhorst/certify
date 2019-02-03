package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// Marshal marshals a private key to PEM format.
func Marshal(pk crypto.PrivateKey) ([]byte, error) {
	switch pk := pk.(type) {
	case *rsa.PrivateKey:
		keyBytes := x509.MarshalPKCS1PrivateKey(pk)
		block := pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: keyBytes,
		}
		return pem.EncodeToMemory(&block), nil
	case *ecdsa.PrivateKey:
		keyBytes, err := x509.MarshalECPrivateKey(pk)
		if err != nil {
			return nil, err
		}
		block := pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: keyBytes,
		}
		return pem.EncodeToMemory(&block), nil
	}

	return nil, errors.New("unsupported private key type")
}
