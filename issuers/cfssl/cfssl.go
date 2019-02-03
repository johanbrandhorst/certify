package cfssl

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/cloudflare/cfssl/api/client"
	"github.com/cloudflare/cfssl/auth"
	"github.com/cloudflare/cfssl/signer"

	"github.com/johanbrandhorst/certify"
	"github.com/johanbrandhorst/certify/internal/csr"
)

// Issuer implements the Issuer interface
// with a Cloudflare CFSSL CA server backend.
//
// URL is required.
type Issuer struct {
	// URL specifies the URL to the CFSSL server.
	URL *url.URL
	// TLSConfig allows configuration of the TLS config
	// used when connecting to the CFSSL server.
	TLSConfig *tls.Config
	// Profile is the profile on the CFSSL server
	// that should be used. If unset, the default
	// profile will be used.
	Profile string
	// Auth optionally configures the authentication
	// that should be used.
	Auth auth.Provider

	remote        client.Remote
	remoteCertPEM []byte
}

// FromClient returns an Issuer using the provided CFSSL API client.
// Any changes to the issuers properties must be done before using it.
func FromClient(v client.Remote) (*Issuer, error) {
	i := &Issuer{
		remote: v,
	}

	// Use the Info endpoint as a PING to check server availability
	resp, err := i.remote.Info([]byte(`{}`))
	if err != nil {
		return nil, err
	}

	i.remoteCertPEM = []byte(resp.Certificate)
	return i, nil
}

// connect and sends a request to validate server availability and
// cache its cert.
func (i *Issuer) connect(ctx context.Context) error {
	if i.TLSConfig != nil {
		i.remote = client.NewServerTLS(i.URL.String(), i.TLSConfig)
	} else {
		i.remote = client.NewServer(i.URL.String())
	}
	// Add context to requests
	i.remote.SetReqModifier(func(req *http.Request, _ []byte) {
		*req = *req.WithContext(ctx)
	})

	// Use the Info endpoint as a PING to check server availability
	resp, err := i.remote.Info([]byte(`{}`))
	if err != nil {
		return err
	}

	i.remoteCertPEM = []byte(resp.Certificate)

	return nil
}

// Issue issues a certificate with the provided options.
func (i *Issuer) Issue(ctx context.Context, commonName string, conf *certify.CertConfig) (*tls.Certificate, error) {
	if i.remote == nil {
		err := i.connect(ctx)
		if err != nil {
			return nil, err
		}
	}

	// Add context to requests
	i.remote.SetReqModifier(func(req *http.Request, _ []byte) {
		*req = *req.WithContext(ctx)
	})

	csrPEM, keyPEM, err := csr.FromCertConfig(commonName, conf)
	if err != nil {
		return nil, err
	}

	req := signer.SignRequest{
		Request: string(csrPEM),
		Profile: i.Profile,
	}

	reqBytes, err := json.Marshal(&req)
	if err != nil {
		return nil, err
	}

	var certPEM []byte
	if i.Auth != nil {
		certPEM, err = i.remote.AuthSign(reqBytes, nil, i.Auth)
	} else {
		certPEM, err = i.remote.Sign(reqBytes)
	}
	if err != nil {
		return nil, err
	}

	caChainPEM := append(append(certPEM, '\n'), i.remoteCertPEM...)
	tlsCert, err := tls.X509KeyPair(caChainPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	// This can't error since it's called in tls.X509KeyPair above successfully
	tlsCert.Leaf, _ = x509.ParseCertificate(tlsCert.Certificate[0])
	return &tlsCert, nil
}
