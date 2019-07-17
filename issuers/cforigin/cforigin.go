package cforigin

import (
	"context"
	"crypto/tls"
	"crypto/x509"

	"github.com/cloudflare/cloudflare-go"
	"github.com/johanbrandhorst/certify"
	"github.com/johanbrandhorst/certify/internal/csr"
)

// Issuer implements the certify.Issuer interface against the
// Cloudflare Origin API. The Auth option must be specified.
// The issuer fields must not be mutated after use.
type Issuer struct {
	// Auth configures how to authenticate against the
	// Cloudflare Origin API. Use either KeyEmailAuth
	// or UserServiceKeyAuth for this field. It must
	// be set.
	Auth auther

	// TimeToLive configures the lifetime of certificates
	// requested from the API. It defaults to 15 years.
	TimeToLive Lifetime
	// ConnOpts can be used to specify options for connecting
	// to the Cloudflare API, such as Organization ID, Retry policy, etc.
	ConnOpts []cloudflare.Option

	api *cloudflare.API
}

// FromClient returns an Issuer using the provided Cloudflare API client.
// Any changes to the issuers properties must be done before using it.
func FromClient(api *cloudflare.API) (*Issuer, error) {
	i := &Issuer{
		api: api,
	}

	// Use the ListZones endpoint as a PING to check server availability
	_, err := i.api.ListZones()
	if err != nil {
		return nil, err
	}

	return i, nil
}

func (i *Issuer) connect(ctx context.Context) error {
	var err error
	opts := append([]cloudflare.Option{cloudflare.UserAgent("go-certify/1.x")}, i.ConnOpts...)
	i.api, err = i.Auth.authenticate(opts...)
	if err != nil {
		return err
	}

	// Use the ListZonesContext endpoint as a PING to check server availability
	_, err = i.api.ListZonesContext(ctx)
	if err != nil {
		return err
	}

	return nil
}

// Issue issues a certificate using the Cloudflare Origin API.
func (i *Issuer) Issue(ctx context.Context, commonName string, conf *certify.CertConfig) (*tls.Certificate, error) {
	if i.api == nil {
		err := i.connect(ctx)
		if err != nil {
			return nil, err
		}
	}

	csrPEM, keyPEM, err := csr.FromCertConfig(commonName, conf)
	if err != nil {
		return nil, err
	}

	lt := i.TimeToLive
	if lt == 0 {
		// Default to 15 years if unset
		lt = LifetimeFifteenYears
	}

	// Docs: https://api.cloudflare.com/#origin-ca-create-certificate
	cert, err := i.api.CreateOriginCertificate(cloudflare.OriginCACertificate{
		CSR:             string(csrPEM),
		RequestValidity: int(lt),
	})
	if err != nil {
		return nil, err
	}

	// Best effort CA chain reproduction
	certChain := []byte(cert.Certificate)
	switch cert.RequestType {
	case "origin-rsa":
		certChain = append(append(certChain, '\n'), cloudflareRSARoot...)
	case "origin-ecc":
		certChain = append(append(certChain, '\n'), cloudflareECCRoot...)
	default:
	}

	tlsCert, err := tls.X509KeyPair(certChain, keyPEM)
	if err != nil {
		return nil, err
	}

	// This can't error since it's called in tls.X509KeyPair above successfully
	tlsCert.Leaf, _ = x509.ParseCertificate(tlsCert.Certificate[0])

	return &tlsCert, nil
}
