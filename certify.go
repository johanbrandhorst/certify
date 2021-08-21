package certify

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"sync"
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

	// Logger configures logging of events such as renewals.
	// Defaults to no logging. Use one of the adapters in
	// https://logur.dev/logur to use with specific
	// logging libraries, or implement the interface yourself.
	Logger Logger

	issueGroup singleflight.Group
	initOnce   sync.Once
}

func (c *Certify) init() {
	if c.Cache == nil {
		c.Cache = &noopCache{}
	}
	if c.Logger == nil {
		c.Logger = &noopLogger{}
	}
	if c.IssueTimeout == 0 {
		c.IssueTimeout = time.Minute
	}
	if c.CertConfig == nil {
		c.CertConfig = &CertConfig{}
	}
	if c.CertConfig.KeyGenerator == nil {
		c.CertConfig.KeyGenerator = &singletonKey{}
	}
}

// GetCertificate implements the GetCertificate TLS config hook.
func (c *Certify) GetCertificate(hello *tls.ClientHelloInfo) (cert *tls.Certificate, err error) {
	c.initOnce.Do(c.init)
	defer func() {
		if err != nil {
			c.Logger.Error("Error getting server certificate", map[string]interface{}{
				"error": err.Error(),
			})
			return
		}
	}()

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

	ctx := getRequestContext(hello)
	return c.getOrRenewCert(ctx, name)
}

// GetClientCertificate implements the GetClientCertificate TLS config hook.
func (c *Certify) GetClientCertificate(cri *tls.CertificateRequestInfo) (cert *tls.Certificate, err error) {
	c.initOnce.Do(c.init)
	defer func() {
		if err != nil {
			c.Logger.Error("Error getting client certificate", map[string]interface{}{
				"error": err.Error(),
			})
			return
		}
	}()
	ctx := getClientRequestContext(cri)
	return c.getOrRenewCert(ctx, c.CommonName)
}

func (c *Certify) getOrRenewCert(ctx context.Context, name string) (*tls.Certificate, error) {
	ctx, cancel := context.WithTimeout(ctx, c.IssueTimeout)
	defer cancel()

	cert, err := c.Cache.Get(ctx, name)
	if err == nil {
		// If we're not within the renewal threshold of the expiry, return the cert
		if time.Now().Before(cert.Leaf.NotAfter.Add(-c.RenewBefore)) {
			return cert, nil
		}
		c.Logger.Debug("Cached certificate found but expiry within renewal threshold", map[string]interface{}{
			"serial": cert.Leaf.SerialNumber.String(),
			"expiry": cert.Leaf.NotAfter.Format(time.RFC3339),
		})
		// Delete the cert, we want to renew it
		_ = c.Cache.Delete(ctx, name)
	} else if err != ErrCacheMiss {
		return nil, err
	}

	// De-duplicate simultaneous requests for the same name
	ch := c.issueGroup.DoChan(name, func() (interface{}, error) {
		c.Logger.Debug("Requesting new certificate from issuer")
		conf := c.CertConfig.Clone()
		conf.appendName(name)

		// Add CommonName to SANS if not already added
		if name != c.CommonName {
			conf.appendName(c.CommonName)
		}

		cert, err := c.Issuer.Issue(ctx, c.CommonName, conf)
		if err != nil {
			return nil, err
		}

		c.Logger.Debug("New certificate issued", map[string]interface{}{
			"serial": cert.Leaf.SerialNumber.String(),
			"expiry": cert.Leaf.NotAfter.Format(time.RFC3339),
		})

		err = c.Cache.Put(ctx, name, cert)
		if err != nil {
			c.Logger.Error("Failed to save certificate in cache", map[string]interface{}{
				"error": err.Error(),
			})
			// Ignore error, it'll just mean we renew again next time
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
