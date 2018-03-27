package certify

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
)

// VaultIssuer implements the Issuer interface with a
// Hashicorp Vault PKI Secrets Engine backend.
//
// VaultURL, Token and Role are required.
type VaultIssuer struct {
	// VaultURL is the URL of the Vault instance.
	VaultURL *url.URL
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
	vaultURL *url.URL,
	role,
	token string,
	allowHTTP bool,
	tlsConfig *tls.Config,
) (*api.Client, error) {
	if vaultURL.Scheme != "https" && !allowHTTP {
		return nil, errors.New("not allowing insecure transport; enable InsecureAllowHTTP if necessary")
	}

	vConf := api.DefaultConfig()

	if tlsConfig != nil {
		vConf.HttpClient.Transport.(*http.Transport).TLSClientConfig = tlsConfig.Clone()
	}

	dl, ok := ctx.Deadline()
	if ok {
		vConf.Timeout = time.Until(dl)
	}
	vConf.Address = vaultURL.String()
	cli, err := api.NewClient(vConf)
	if err != nil {
		return nil, err
	}

	cli.SetToken(token)
	return cli, nil
}

// Connect connects to Vault. If not called,
// a connection will be made in the first Issue call.
func (v *VaultIssuer) Connect(ctx context.Context) error {
	var err error
	v.cli, err = connect(ctx, v.VaultURL, v.Role, v.Token, v.InsecureAllowHTTP, v.TLSConfig)
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

	// https://www.vaultproject.io/api/secret/pki/index.html#parameters-6
	opts := map[string]interface{}{
		"common_name":          commonName,
		"exclude_cn_from_sans": true,
		// Defaults, but can't hurt specifying them
		"private_key_format": "der", // Actually returns PEM because of below
		"format":             "pem",
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
