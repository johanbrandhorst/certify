package certify

import (
	"context"
	"crypto/tls"
	"net"
)

// Issuer is the interface that must be implemented
// by certificate issuers.
type Issuer interface {
	Issue(context.Context, string, *CertConfig) (*tls.Certificate, error)
}

// CertConfig configures the specifics of the certificate
// requested from the Issuer.
type CertConfig struct {
	SubjectAlternativeNames   []string
	IPSubjectAlternativeNames []net.IP
}

// Clone makes a deep copy of the CertConfig.
func (cc *CertConfig) Clone() *CertConfig {
	newCC := new(CertConfig)
	if cc == nil {
		return newCC
	}

	newCC.SubjectAlternativeNames = cc.SubjectAlternativeNames
	newCC.IPSubjectAlternativeNames = cc.IPSubjectAlternativeNames
	return newCC
}

func (cc *CertConfig) appendName(name string) {
	if ip := net.ParseIP(name); ip != nil {
		cc.IPSubjectAlternativeNames = append(cc.IPSubjectAlternativeNames, ip)
	} else {
		cc.SubjectAlternativeNames = append(cc.SubjectAlternativeNames, name)
	}
}
