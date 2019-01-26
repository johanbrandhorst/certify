package vault

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/hashicorp/vault/api"

	"github.com/johanbrandhorst/certify"
)

// Issuer implements the Issuer interface with a
// Hashicorp Vault PKI Secrets Engine backend.
//
// URL, Token and Role are required.
type Issuer struct {
	// URL is the URL of the Vault instance.
	URL *url.URL
	// Token is the Vault secret token that should be used
	// when issuing certificates.
	Token string
	// Role is the Vault Role that should be used
	// when issuing certificates.
	Role string
	// TLSConfig allows configuration of the TLS config
	// used when connecting to the Vault server.
	TLSConfig *tls.Config
	// TimeToLive configures the lifetime of certificates
	// requested from the Vault server.
	TimeToLive time.Duration
	// OtherSubjectAlternativeNames defines custom OID/UTF8-string SANs.
	// The format is the same as OpenSSL: <oid>;<type>:<value> where the only current valid <type> is UTF8.
	OtherSubjectAlternativeNames []string

	cli *api.Client
}

func connect(
	ctx context.Context,
	URL *url.URL,
	role,
	token string,
	tlsConfig *tls.Config,
) (*api.Client, error) {
	vConf := api.DefaultConfig()

	if tlsConfig != nil {
		vConf.HttpClient.Transport.(*http.Transport).TLSClientConfig = tlsConfig.Clone()
	}

	dl, ok := ctx.Deadline()
	if ok {
		vConf.Timeout = time.Until(dl)
	}
	vConf.Address = URL.String()
	cli, err := api.NewClient(vConf)
	if err != nil {
		return nil, err
	}

	cli.SetToken(token)
	return cli, nil
}

// Connect connects to Vault. If not called,
// a connection will be made in the first Issue call.
func (v *Issuer) Connect(ctx context.Context) error {
	var err error
	v.cli, err = connect(ctx, v.URL, v.Role, v.Token, v.TLSConfig)
	return err
}

// Issue issues a certificate from the configured Vault backend,
// establishing a connection if one doesn't already exist.
func (v *Issuer) Issue(ctx context.Context, commonName string, conf *certify.CertConfig) (*tls.Certificate, error) {
	if v.cli == nil {
		err := v.Connect(ctx)
		if err != nil {
			return nil, err
		}
	}

	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	keyBytes, err := x509.MarshalECPrivateKey(pk)
	if err != nil {
		return nil, err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	template := &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Subject: pkix.Name{
			CommonName: commonName,
		},
	}

	if conf != nil {
		template.DNSNames = conf.SubjectAlternativeNames
		template.IPAddresses = conf.IPSubjectAlternativeNames
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, template, pk)
	if err != nil {
		return nil, err
	}

	opts := csrOpts{
		CSR:               csr,
		CommonName:        commonName,
		ExcludeCNFromSANS: true,
		Format:            "pem",
		OtherSans:         v.OtherSubjectAlternativeNames,
		TimeToLive:        ttl(v.TimeToLive),
	}

	secret, err := v.signCSR(ctx, opts)
	if err != nil {
		return nil, err
	}

	// https://www.vaultproject.io/api/secret/pki/index.html#sample-response-15
	certPEM := []byte(secret.Data["certificate"].(string))
	caChainPEM := certPEM
	if caChain, ok := secret.Data["ca_chain"]; ok {
		for _, pemData := range caChain.([]interface{}) {
			caChainPEM = append(append(caChainPEM, '\n'), []byte(pemData.(string))...)
		}
	} else if ca, ok := secret.Data["issuing_ca"]; ok {
		caChainPEM = append(append(caChainPEM, '\n'), []byte(ca.(string))...)
	}

	tlsCert, err := tls.X509KeyPair(caChainPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	// This can't error since it's called in tls.X509KeyPair above successfully
	tlsCert.Leaf, _ = x509.ParseCertificate(tlsCert.Certificate[0])
	return &tlsCert, nil
}

func (v *Issuer) signCSR(ctx context.Context, opts csrOpts) (*api.Secret, error) {
	r := v.cli.NewRequest("PUT", "/v1/pki/sign/"+v.Role)
	if err := r.SetJSONBody(opts); err != nil {
		return nil, err
	}

	resp, err := v.cli.RawRequestWithContext(ctx, r)
	if resp != nil {
		defer resp.Body.Close()
	}
	if resp != nil && resp.StatusCode == 404 {
		secret, parseErr := api.ParseSecret(resp.Body)
		switch parseErr {
		case nil:
		case io.EOF:
			return nil, nil
		default:
			return nil, err
		}
		if secret != nil && (len(secret.Warnings) > 0 || len(secret.Data) > 0) {
			return secret, err
		}
	}
	if err != nil {
		return nil, err
	}

	return api.ParseSecret(resp.Body)
}
