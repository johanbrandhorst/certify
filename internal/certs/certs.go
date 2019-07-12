package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

// Key represents a private key
type Key struct {
	PEM []byte
	Key *rsa.PrivateKey
}

// Cert represents a x509.Certificate
type Cert struct {
	PEM  []byte
	Cert *x509.Certificate
}

// GenerateCertAndKey generates a cert and key, suitable for use
// when signing CSR.
func GenerateCertAndKey() (*Cert, *Key, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "Certify Test Cert",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
	if err != nil {
		return nil, nil, err
	}

	k := &Key{
		Key: priv,
		PEM: pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		}),
	}
	crt, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}
	c := &Cert{
		Cert: crt,
		PEM: pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: derBytes,
		}),
	}
	return c, k, nil
}
