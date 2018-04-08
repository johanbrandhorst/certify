package certify

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/cloudflare/cfssl/signer"

	"github.com/cloudflare/cfssl/api/client"
	"github.com/cloudflare/cfssl/auth"
	"github.com/cloudflare/cfssl/csr"
)

// CFSSLIssuer implements the Issuer interface
// with a Cloudflare CFSSL CA server backend.
type CFSSLIssuer struct {
	//
	URL *url.URL

	TLSConfig *tls.Config

	Profile string

	Auth auth.Provider

	remote        client.Remote
	remoteCertPEM []byte
	csrGenerator  *csr.Generator
}

// Connect creates a new connection to the CFSSL server
// and sends a request to validate server availability. If not called,
// a connection will be made in the first Issue call.
func (m *CFSSLIssuer) Connect(ctx context.Context) error {
	m.remote = client.NewServerTLS(m.URL.String(), m.TLSConfig)
	// Add context to requests
	m.remote.SetReqModifier(func(req *http.Request, _ []byte) {
		*req = *req.WithContext(ctx)
	})

	// Use the Info endpoint as a PING to check server availability
	resp, err := m.remote.Info([]byte(`{}`))
	if err != nil {
		return err
	}

	m.remoteCertPEM = []byte(resp.Certificate)

	m.csrGenerator = &csr.Generator{Validator: func(req *csr.CertificateRequest) error {
		return nil
	}}

	return nil
}

// Issue issues a certificate with the provided options
func (m *CFSSLIssuer) Issue(ctx context.Context, commonName string, conf *CertConfig) (*tls.Certificate, error) {
	if m.remote == nil {
		err := m.Connect(ctx)
		if err != nil {
			return nil, err
		}
	}

	// Add context to requests
	m.remote.SetReqModifier(func(req *http.Request, _ []byte) {
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

	csrPEM, keyPEM, err := m.csrGenerator.ProcessRequest(&csrReq)
	if err != nil {
		return nil, err
	}

	req := signer.SignRequest{
		Request: string(csrPEM),
		Profile: m.Profile,
	}

	reqBytes, err := json.Marshal(&req)
	if err != nil {
		return nil, err
	}

	var certPEM []byte
	if m.Auth != nil {
		certPEM, err = m.remote.AuthSign(reqBytes, nil, m.Auth)
	} else {
		certPEM, err = m.remote.Sign(reqBytes)
	}
	if err != nil {
		return nil, err
	}

	caChainPEM := append(append(certPEM, '\n'), m.remoteCertPEM...)
	tlsCert, err := tls.X509KeyPair(caChainPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	// This can't error since it's called in tls.X509KeyPair above successfully
	tlsCert.Leaf, _ = x509.ParseCertificate(tlsCert.Certificate[0])
	return &tlsCert, nil
}
