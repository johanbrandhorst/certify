package certbot

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cenk/backoff"
	"github.com/hashicorp/vault/api"
)

// VaultIssuer implements the Issuer interface with a
// Hashicorp Vault PKI Secrets backend.
//
// VaultURLs, Token and Role are required.
type VaultIssuer struct {
	// VaultURLs is a slice of URLs that will be
	// used to connect Vault. At least one URL is required,
	// and several can be used in a High Availability Vault setup.
	// The client will cycle through the specified URLs when attempting
	// to establish a connection.
	VaultURLs []*url.URL
	// Token is the Vault secret token that should be used
	// when issuing certificates.
	Token string
	// Role is the Vault Role that should be used
	// when issuing certificates.
	Role string
	// InsecureAllowHTTP allows the use of HTTP to send
	// the issued certificate and private key.
	// WARNING: DO NOT USE UNLESS ABSOLUTELY NECESSARY.
	InsecureAllowHTTP bool
	// TLSConfig allows configuration of the TLS config
	// used when connecting to the Vault server.
	TLSConfig *tls.Config

	cli *api.Client
}

func connect(
	ctx context.Context,
	vaultURLs []*url.URL,
	role,
	token string,
	allowHTTP bool,
	tlsConfig *tls.Config,
) (*api.Client, error) {
	bk := backoff.NewExponentialBackOff()
	// Ensure perpetual retries
	bk.MaxElapsedTime = 0

	vConf := api.DefaultConfig()

	if tlsConfig != nil {
		vConf.HttpClient.Transport.(*http.Transport).TLSClientConfig = tlsConfig.Clone()
	}

	dl, ok := ctx.Deadline()
	if ok {
		vConf.Timeout = dl.Sub(time.Now())
	}

	urlIndex := 0

	var cli *api.Client
	connect := func() error {
		u := vaultURLs[urlIndex]
		// Cycle urlIndex between 0 - len(vaultURLs)-1
		urlIndex = (urlIndex + 1) % len(vaultURLs)
		if u.Scheme != "https" && !allowHTTP {
			return backoff.Permanent(errors.New("not allowing insecure transport"))
		}
		vConf.Address = u.String()
		var err error
		cli, err = api.NewClient(vConf)
		if err != nil {
			return err
		}

		cli.SetToken(token)
		data, err := cli.Logical().Read("pki/roles/" + role)
		if err != nil {
			return err
		}

		if data == nil {
			return backoff.Permanent(errors.New("role does not exist"))
		}

		return nil
	}

	err := backoff.Retry(connect, backoff.WithContext(bk, ctx))
	if err != nil {
		if e, ok := err.(*backoff.PermanentError); ok {
			return nil, e.Err
		}

		return nil, err
	}

	return cli, nil
}

// Connect connects to Vault. If not called,
// a connection will be made in the first Issue call.
func (v *VaultIssuer) Connect(ctx context.Context) error {
	var err error
	v.cli, err = connect(ctx, v.VaultURLs, v.Role, v.Token, v.InsecureAllowHTTP, v.TLSConfig)
	return err
}

// Issue issues a certificate from one of the configured Vault backends,
// establishing a connection if one doesn't already exist.
func (v *VaultIssuer) Issue(ctx context.Context, commonName string, conf *CertConfig) (*tls.Certificate, error) {
	if v.cli == nil {
		err := v.Connect(ctx)
		if err != nil {
			return nil, err
		}
	}

	if len(commonName) > 64 {
		// https://www.ietf.org/rfc/rfc3280.txt
		// ub-common-name-length INTEGER ::= 64
		return nil, errors.New("common name cannot be larger than 64 bytes")
	}

	// https://www.vaultproject.io/api/secret/pki/index.html#parameters-6
	opts := map[string]interface{}{
		"common_name": commonName,
		// Defaults, but can't hurt specifying them
		"private_key_format":   "der", // Actually returns PEM because of below
		"format":               "pem",
		"exclude_cn_from_sans": true,
	}

	if conf != nil {
		if len(conf.SubjectAlternativeNames) > 0 {
			opts["alt_names"] = strings.Join(conf.SubjectAlternativeNames, ",")
		}

		if len(conf.IPSubjectAlternativeNames) > 0 {
			ips := make([]string, 0, len(conf.IPSubjectAlternativeNames))
			for _, ip := range conf.IPSubjectAlternativeNames {
				ips = append(ips, ip.String())
			}
			opts["ip_sans"] = strings.Join(ips, ",")
		}

		if len(conf.OtherSubjectAlternativeNames) > 0 {
			opts["other_alt_names"] = strings.Join(conf.OtherSubjectAlternativeNames, ",")
		}

		if conf.TimeToLive > 0 {
			opts["ttl"] = conf.TimeToLive.String()
		}
	}

	secret, err := v.cli.Logical().Write("pki/issue/"+v.Role, opts)
	if err != nil {
		return nil, err
	}

	// https://www.vaultproject.io/api/secret/pki/index.html#sample-response-8
	certPEM := secret.Data["certificate"].(string)
	keyPEM := secret.Data["private_key"].(string)

	caChainPEM := certPEM
	if caChain, ok := secret.Data["ca_chain"]; ok {
		for _, pemData := range caChain.([]string) {
			caChainPEM = caChainPEM + "\n" + pemData
		}
	} else if ca, ok := secret.Data["issuing_ca"]; ok {
		caChainPEM = caChainPEM + "\n" + ca.(string)
	}

	tlsCert, err := tls.X509KeyPair([]byte(caChainPEM), []byte(keyPEM))
	if err != nil {
		return nil, err
	}

	// This can't error since it's called in tls.X509KeyPair above successfully
	tlsCert.Leaf, _ = x509.ParseCertificate(tlsCert.Certificate[0])
	return &tlsCert, nil
}
