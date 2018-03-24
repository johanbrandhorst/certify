package certbot

import (
	"context"
	"crypto/tls"
	"net"
	"time"
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
	// OtherSubjectAlternativeNames defines custom OID/UTF8-string SANs.
	// The format is the same as OpenSSL: <oid>;<type>:<value> where the only current valid type is UTF8.
	OtherSubjectAlternativeNames []string
	// TimeToLive is how long each certificate should be valid for,
	// from the time of issue.
	TimeToLive time.Duration
}

// Clone makes a deep copy of the CertConfig.
func (cc *CertConfig) Clone() *CertConfig {
	newCC := new(CertConfig)
	if cc == nil {
		return newCC
	}

	newCC.SubjectAlternativeNames = cc.SubjectAlternativeNames
	newCC.IPSubjectAlternativeNames = cc.IPSubjectAlternativeNames
	newCC.OtherSubjectAlternativeNames = cc.OtherSubjectAlternativeNames
	newCC.TimeToLive = cc.TimeToLive
	return newCC
}
