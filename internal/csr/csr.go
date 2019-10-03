package csr

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"

	"github.com/johanbrandhorst/certify"
	"github.com/johanbrandhorst/certify/internal/keys"
)

// FromCertConfig creates a CSR and private key from the input config and common name.
// It returns the CSR and private key in PEM format.
func FromCertConfig(commonName string, conf *certify.CertConfig) ([]byte, []byte, error) {
	pk, err := conf.KeyGenerator.Generate()
	if err != nil {
		return nil, nil, err
	}

	keyPEM, err := keys.Marshal(pk)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
	}

	if conf != nil {
		template.DNSNames = conf.SubjectAlternativeNames
		template.IPAddresses = conf.IPSubjectAlternativeNames
		template.URIs = conf.URISubjectAlternativeNames
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, template, pk)
	if err != nil {
		return nil, nil, err
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	})

	return csrPEM, keyPEM, nil
}
