package certify

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"time"
)

// Certify implements automatic certificate acquisition
// via the configured Issuer.
//
// CommonName and Issuer are required.
// It is recommended that you specify a Cache to prevent requesting a
// new certificate for every incoming connection.
type Certify struct {
	// CommonName is the Certificate Common Name
	// that will be used when issuing certificates.
	// This can be a DNS record or a regular name.
	CommonName string

	// Issuer is the certificate issuer to use.
	Issuer Issuer

	// RenewBefore configures how long before
	// expiry a certificate should be considered too
	// old to use when fetched from the cache.
	RenewBefore time.Duration

	// Cache is the Cache implementation to use.
	Cache Cache

	// CertConfig is the certificate configuration that
	// should be used. It can be specified to set explicit
	// requirements of certificates issued.
	CertConfig *CertConfig

	// IssueTimeout is the upper bound of time allowed
	// per certificate call. Defaults to 1 minute.
	IssueTimeout time.Duration
}

// GetCertificate implements the GetCertificate TLS config hook.
func (c *Certify) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := strings.ToLower(hello.ServerName)
	if name == "" {
		return nil, errors.New("missing server name")
	}
	if strings.ContainsAny(name, `/\`) {
		return nil, errors.New("server name contains invalid character")
	}

	// Remove ending dot, if any
	name = strings.TrimSuffix(name, ".")

	// Remove port, if used
	if strings.Contains(name, ":") {
		name = strings.Split(name, ":")[0]
	}

	issueTimeout := c.IssueTimeout
	if issueTimeout == 0 {
		issueTimeout = time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), issueTimeout)
	defer cancel()
	return c.getOrRenewCert(ctx, name)
}

// GetClientCertificate implements the GetClientCertificate TLS config hook.
func (c *Certify) GetClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	issueTimeout := c.IssueTimeout
	if issueTimeout == 0 {
		issueTimeout = time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), issueTimeout)
	defer cancel()
	// Request certificate for the configured Common Name
	return c.getOrRenewCert(ctx, c.CommonName)
}

func (c *Certify) getOrRenewCert(ctx context.Context, name string) (*tls.Certificate, error) {
	if c.Cache != nil {
		cert, err := c.Cache.Get(ctx, name)
		if err == nil {
			// If we're not within the renewal threshold of the expiry, return the cert
			if time.Now().Before(cert.Leaf.NotAfter.Add(-c.RenewBefore)) {
				return cert, nil
			}
			// Delete the cert, we want to renew it
			_ = c.Cache.Delete(ctx, name)
		} else if err != ErrCacheMiss {
			return nil, err
		}
	}

	conf := c.CertConfig.Clone()
	if ip := net.ParseIP(name); ip != nil {
		conf.IPSubjectAlternativeNames = append(conf.IPSubjectAlternativeNames, ip)
	} else {
		conf.SubjectAlternativeNames = append(conf.SubjectAlternativeNames, name)
	}

	cert, err := c.Issuer.Issue(ctx, c.CommonName, conf)
	if err != nil {
		return nil, err
	}

	if c.Cache != nil {
		// Ignore error, it'll just mean we renew again next time
		_ = c.Cache.Put(ctx, name, cert)
	}

	return cert, nil
}
