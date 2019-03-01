package certify_test

import (
	"testing"

	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestCertify(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Certify Suite")
}

func generateCertAndKey(SAN string, IPSAN net.IP, keyFunc keyGeneratorFunc) (*tls.Certificate, error) {
	priv, err := keyFunc.Generate()
	if err != nil {
		return nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
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
		DNSNames:              []string{SAN},
		IPAddresses:           []net.IP{IPSAN},
	}

	var (
		pubKey     crypto.PublicKey
		encodedKey []byte
	)
	switch p := priv.(type) {
	case *rsa.PrivateKey:
		pubKey = p.Public()
		encodedKey = x509.MarshalPKCS1PrivateKey(p)
	case *ecdsa.PrivateKey:
		pubKey = p.Public()
		encoded, err := x509.MarshalECPrivateKey(p)
		if err != nil {
			return nil, err
		}
		encodedKey = encoded
	default:
		return nil, fmt.Errorf("Unsupported key type")
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, pubKey, priv)
	if err != nil {
		return nil, err
	}
	certOut := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})
	keyOut := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: encodedKey,
	})

	cert, err := tls.X509KeyPair(certOut, keyOut)
	if err != nil {
		return nil, err
	}

	return &cert, nil
}
