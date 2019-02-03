package certify

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"strings"
	"time"

	"golang.org/x/sync/singleflight"
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

	issueGroup singleflight.Group
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

	return c.getOrRenewCert(name)
}

// GetClientCertificate implements the GetClientCertificate TLS config hook.
func (c *Certify) GetClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return c.getOrRenewCert(c.CommonName)
}

func (c *Certify) getOrRenewCert(name string) (*tls.Certificate, error) {
	issueTimeout := c.IssueTimeout
	if issueTimeout == 0 {
		issueTimeout = time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), issueTimeout)
	defer cancel()

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

	// De-duplicate simultaneous requests
	ch := c.issueGroup.DoChan("issue", func() (interface{}, error) {
		conf := c.CertConfig.Clone()
		conf.appendName(name)

		if conf.KeyGenerator == nil {
			conf.KeyGenerator = keyGeneratorFunc(func() (crypto.PrivateKey, error) {
				return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			})
		}

		// Add CommonName to SANS if not already added
		if name != c.CommonName {
			conf.appendName(c.CommonName)
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
	})

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			return nil, res.Err
		}
		return res.Val.(*tls.Certificate), nil
	}
}

type keyGeneratorFunc func() (crypto.PrivateKey, error)

func (kgf keyGeneratorFunc) Generate() (crypto.PrivateKey, error) {
	return kgf()
}
