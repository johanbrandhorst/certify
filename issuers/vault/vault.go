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
	"net/http"
	"net/url"
	"strings"
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

	csr := &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Subject: pkix.Name{
			CommonName: commonName,
		},
	}

	if conf != nil {
		csr.DNSNames = conf.SubjectAlternativeNames
		csr.IPAddresses = conf.IPSubjectAlternativeNames
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, csr, pk)
	if err != nil {
		return nil, err
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})

	// https://www.vaultproject.io/api/secret/pki/index.html#parameters-14
	opts := map[string]interface{}{
		"csr":                  string(csrPEM),
		"common_name":          commonName,
		"exclude_cn_from_sans": true,
		// Default value, but can't hurt specifying it
		"format": "pem",
	}

	if len(v.OtherSubjectAlternativeNames) > 0 {
		opts["other_sans"] = strings.Join(v.OtherSubjectAlternativeNames, ",")
	}

	if v.TimeToLive > 0 {
		opts["ttl"] = v.TimeToLive.String()
	}

	secret, err := v.cli.Logical().Write("pki/sign/"+v.Role, opts)
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
