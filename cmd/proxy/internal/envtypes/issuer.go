package envtypes

import (
	"errors"
	"net/url"
	"strings"
	"time"
)

// Issuer is an enumeration of supported issuers
type Issuer int

// Supported issuers
const (
	VaultIssuer = iota
	CFSSLIssuer
	AWSIssuer
)

// UnmarshalText implements encoding.TextUnmarshaler for issuer.
func (i *Issuer) UnmarshalText(in []byte) error {
	switch strings.ToLower(string(in)) {
	case "vault", "hashicorp":
		*i = VaultIssuer
	case "cfssl", "cloudflare":
		*i = CFSSLIssuer
	case "aws", "amazon", "acmpca", "awscmpca":
		*i = AWSIssuer
	default:
		return errors.New(`invalid issuer specified, supported issuers are "vault", "cfssl" and "aws"`)
	}
	return nil
}

// Vault issuer configuration.
type Vault struct {
	URL                          url.URL       `desc:"The URL of the Vault instance."`
	Token                        string        `desc:"The Vault secret token that should be used when issuing certificates."`
	Mount                        string        `default:"pki" desc:"The name under which the PKI secrets engine is mounted."`
	Role                         string        `desc:"The Vault Role that should be used when issuing certificates."`
	CACertPath                   string        `envconfig:"CA_CERT_PATH" desc:"The path to the CA cert to use when connecting to Vault. If not set, will use publically trusted CAs."`
	TimeToLive                   time.Duration `split_words:"true" default:"720h" desc:"Configures the lifetime of certificates requested from the Vault server."`
	URISubjectAlternativeNames   []string      `envconfig:"URI_SUBJECT_ALTERNATIVE_NAMES" desc:"Custom URI SANs that should be used in issued certificates. The format is a URI and must match the value specified in allowed_uri_sans, eg spiffe://hostname/foobar."`
	OtherSubjectAlternativeNames []string      `envconfig:"OTHER_SUBJECT_ALTERNATIVE_NAMES" desc:"Custom OID/UTF8-string SANs that should be used in issued certificates. The format is the same as OpenSSL: <oid>;<type>:<value> where the only current valid <type> is UTF8."`
}

// CFSSL issuer configuration.
type CFSSL struct {
	URL        url.URL `desc:"The URL of the CFSSL server."`
	CACertPath string  `envconfig:"CA_CERT_PATH" desc:"The path to the CA cert to use when connecting to Vault. If not set, will use publically trusted CAs."`
	Profile    string  `desc:"The profile on the CFSSL server that should be used. If unset, the default profile will be used."`
	AuthKey    string  `split_words:"true" desc:"Optionally defines an authentication key to use when connecting to CFSSL."`
}

// AWS issuer configuration.
type AWS struct {
	Region                  string `desc:"The AWS region to use."`
	AccessKeyID             string `envconfig:"ACCESS_KEY_ID" desc:"The AWS access key ID to use for authenticating with AWS."`
	AccessKeySecret         string `split_words:"true" desc:"The AWS access key secret to use for authenticating with AWS."`
	CertificateAuthorityARN string `envconfig:"CERTIFICATE_AUTHORITY_ARN" desc:"The ARN of a pre-created CA which will be used to issue the certificates."`
	TimeToLive              int    `default:"30" desc:"The lifetime of certificates requested from the AWS CA, in number of days."`
}
