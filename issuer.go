package certify

import (
	"context"
	"crypto"
	"crypto/tls"
	"net"
	"net/url"
)

// Issuer is the interface that must be implemented
// by certificate issuers.
type Issuer interface {
	Issue(context.Context, string, *CertConfig) (*tls.Certificate, error)
}

// KeyGenerator defines an interface used to generate a private key.
type KeyGenerator interface {
	Generate() (crypto.PrivateKey, error)
}

// CertConfig configures the specifics of the certificate
// requested from the Issuer.
type CertConfig struct {
	SubjectAlternativeNames    []string
	IPSubjectAlternativeNames  []net.IP
	URISubjectAlternativeNames []*url.URL
	// KeyGenerator is used to create new private keys
	// for CSR requests. If not defined, defaults to ECDSA P256.
	// Only ECDSA and RSA keys are supported.
	// This is guaranteed to be provided in Issue calls.
	KeyGenerator KeyGenerator
}

// Clone makes a deep copy of the CertConfig.
func (cc *CertConfig) Clone() *CertConfig {
	newCC := new(CertConfig)
	if cc == nil {
		return newCC
	}

	newCC.SubjectAlternativeNames = cc.SubjectAlternativeNames
	newCC.IPSubjectAlternativeNames = cc.IPSubjectAlternativeNames
	newCC.URISubjectAlternativeNames = cc.URISubjectAlternativeNames
	newCC.KeyGenerator = cc.KeyGenerator
	return newCC
}

func (cc *CertConfig) appendName(name string) {
	if ip := net.ParseIP(name); ip != nil {
		cc.IPSubjectAlternativeNames = append(cc.IPSubjectAlternativeNames, ip)
	} else {
		cc.SubjectAlternativeNames = append(cc.SubjectAlternativeNames, name)
	}
}
