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
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/signer"

	"github.com/johanbrandhorst/certify"
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
	csrGenerator  *csr.Generator
}

// FromClient returns an Issuer using the provided CFSSL API client.
// Any changes to the issuers properties must be done before using it.
func FromClient(v client.Remote) (*Issuer, error) {
	i := &Issuer{
		remote: v,
		csrGenerator: &csr.Generator{Validator: func(req *csr.CertificateRequest) error {
			return nil
		}},
	}

	// Use the Info endpoint as a PING to check server availability
	resp, err := i.remote.Info([]byte(`{}`))
	if err != nil {
		return nil, err
	}

	i.remoteCertPEM = []byte(resp.Certificate)
	return i, nil
}

// Connect creates a new connection to the CFSSL server
// and sends a request to validate server availability. If not called,
// a connection will be made in the first Issue call.
func (i *Issuer) Connect(ctx context.Context) error {
	i.remote = client.NewServerTLS(i.URL.String(), i.TLSConfig)
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

	i.csrGenerator = &csr.Generator{Validator: func(req *csr.CertificateRequest) error {
		return nil
	}}

	return nil
}

// Issue issues a certificate with the provided options
func (i *Issuer) Issue(ctx context.Context, commonName string, conf *certify.CertConfig) (*tls.Certificate, error) {
	if i.remote == nil {
		err := i.Connect(ctx)
		if err != nil {
			return nil, err
		}
	}

	// Add context to requests
	i.remote.SetReqModifier(func(req *http.Request, _ []byte) {
		*req = *req.WithContext(ctx)
	})

	csrReq := csr.CertificateRequest{
		CN:         commonName,
		KeyRequest: csr.NewBasicKeyRequest(),
	}

	if conf != nil {
		csrReq.Hosts = append(csrReq.Hosts, conf.SubjectAlternativeNames...)
		for _, ip := range conf.IPSubjectAlternativeNames {
			csrReq.Hosts = append(csrReq.Hosts, ip.String())
		}
	}

	csrPEM, keyPEM, err := i.csrGenerator.ProcessRequest(&csrReq)
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
