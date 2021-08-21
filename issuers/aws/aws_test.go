package aws_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	api "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	"github.com/aws/aws-sdk-go-v2/service/acmpca/types"

	"github.com/johanbrandhorst/certify"
	"github.com/johanbrandhorst/certify/issuers/aws"
)

func TestIssuer(t *testing.T) {
	t.Run("It issues a certificate", func(t *testing.T) {
		caARN := "someARN"
		certARN := "anotherARN"
		caCert, caKey, err := generateCertAndKey()
		if err != nil {
			t.Fatal(err)
		}
		ttl := 25
		server := httptest.NewTLSServer(&fakeACMPCA{
			t:            t,
			certARN:      certARN,
			caARN:        caARN,
			caCert:       caCert,
			caKey:        caKey,
			validityDays: ttl,
		})

		client := acmpca.NewFromConfig(api.Config{
			HTTPClient: server.Client(),
			EndpointResolver: api.EndpointResolverFunc(func(service, region string) (api.Endpoint, error) {
				return api.Endpoint{
					URL: server.URL,
				}, nil
			}),
		})
		iss := &aws.Issuer{
			CertificateAuthorityARN: caARN,
			Client:                  client,
			TimeToLive:              ttl,
		}
		cn := "somename.com"
		conf := &certify.CertConfig{
			SubjectAlternativeNames:   []string{"extraname.com", "otherextraname.com"},
			IPSubjectAlternativeNames: []net.IP{net.IPv4(1, 2, 3, 4), net.IPv6loopback},
			KeyGenerator: keyGeneratorFunc(func() (crypto.PrivateKey, error) {
				return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			}),
		}
		tlsCert, err := iss.Issue(context.Background(), cn, conf)
		if err != nil {
			t.Fatal(err)
		}

		if tlsCert.Leaf == nil {
			t.Fatal("tlsCert.Leaf should be populated by Issue to track expiry")
		}
		if tlsCert.Leaf.Subject.CommonName != cn {
			t.Fatalf("Unexpected Common name %s, wanted %s", tlsCert.Leaf.Subject.CommonName, cn)
		}
		if len(tlsCert.Leaf.DNSNames) != len(conf.SubjectAlternativeNames) {
			t.Fatalf("Unexpected number of DNS names set, got %d wanted %d", len(tlsCert.Leaf.DNSNames), len(conf.SubjectAlternativeNames))
		}
		for i, dnsName := range tlsCert.Leaf.DNSNames {
			if conf.SubjectAlternativeNames[i] != dnsName {
				t.Fatalf("Unexpected DNS name %s, wanted %s", dnsName, conf.SubjectAlternativeNames[i])
			}
		}
		if len(tlsCert.Leaf.IPAddresses) != len(conf.IPSubjectAlternativeNames) {
			t.Fatalf("Unexpected number of IP addresses set, got %d wanted %d", len(tlsCert.Leaf.IPAddresses), len(conf.IPSubjectAlternativeNames))
		}
		for i, ip := range tlsCert.Leaf.IPAddresses {
			if !ip.Equal(conf.IPSubjectAlternativeNames[i]) {
				t.Fatalf("Unexpected IP address %s, wanted %s", ip, conf.IPSubjectAlternativeNames[i])
			}
		}

		// Check that chain is included
		if len(tlsCert.Certificate) != 2 {
			t.Fatalf("Unexpected number of certificates in chain, got %d wanted %d", len(tlsCert.Certificate), 2)
		}
		crt, err := x509.ParseCertificate(tlsCert.Certificate[1])
		if err != nil {
			t.Fatal(err)
		}
		if crt.Subject.SerialNumber != tlsCert.Leaf.Issuer.SerialNumber {
			t.Fatalf("Unexpected serial number, got %s wanted %s", crt.Subject.SerialNumber, tlsCert.Leaf.Issuer.SerialNumber)
		}
		if tlsCert.Leaf.NotBefore.After(time.Now()) {
			t.Fatalf("Unexpected NotBefore time, got %s wanted > %s", tlsCert.Leaf.NotBefore, time.Now())
		}
		if tlsCert.Leaf.NotAfter.Before(time.Now().AddDate(0, 0, iss.TimeToLive).Add(-5*time.Second)) ||
			tlsCert.Leaf.NotAfter.After(time.Now().AddDate(0, 0, iss.TimeToLive).Add(5*time.Second)) {
			t.Fatalf(
				"Unexpected NotAfter time, got %s wanted in [%s, %s]",
				tlsCert.Leaf.NotAfter,
				time.Now().AddDate(0, 0, iss.TimeToLive).Add(-5*time.Second),
				time.Now().AddDate(0, 0, iss.TimeToLive).Add(5*time.Second),
			)
		}
	})
}

type fakeACMPCA struct {
	t            *testing.T
	caARN        string
	certARN      string
	caCert       *cert
	caKey        *key
	validityDays int

	signedCertPEM []byte
}

func (f *fakeACMPCA) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Header.Get("X-Amz-Target") {
	case "ACMPrivateCA.GetCertificateAuthorityCertificate":
		f.ServeGetCertificateAuthorityCertificate(w, r)
		return
	case "ACMPrivateCA.IssueCertificate":
		f.ServeIssueCertificate(w, r)
		return
	case "ACMPrivateCA.GetCertificate":
		f.ServeGetCertificate(w, r)
		return
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (f *fakeACMPCA) ServeGetCertificateAuthorityCertificate(w http.ResponseWriter, r *http.Request) {
	input := struct {
		CertificateAuthorityARN string `json:"CertificateAuthorityARN,omitempty"`
	}{}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if input.CertificateAuthorityARN != f.caARN {
		http.Error(w, "unknown CA ARN", http.StatusNotFound)
		return
	}
	output := struct {
		Certificate string `json:"Certificate,omitempty"`
	}{
		Certificate: string(f.caCert.pem),
	}
	if err := json.NewEncoder(w).Encode(&output); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (f *fakeACMPCA) ServeIssueCertificate(w http.ResponseWriter, r *http.Request) {
	input := struct {
		CertificateAuthorityARN string                 `json:"CertificateAuthorityARN,omitempty"`
		CSRPem                  []byte                 `json:"Csr,omitempty"`
		SigningAlgorithm        types.SigningAlgorithm `json:"SigningAlgorithm,omitempty"`
		Validity                types.Validity         `json:"Validity,omitempty"`
	}{}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if input.CertificateAuthorityARN != f.caARN {
		http.Error(w, "unknown CA ARN", http.StatusNotFound)
		return
	}
	if input.Validity.Type != types.ValidityPeriodTypeDays {
		http.Error(w, "unexpected validity period type", http.StatusBadRequest)
		return
	}
	if int(*input.Validity.Value) != f.validityDays {
		http.Error(w, "unexpected validity period", http.StatusBadRequest)
		return
	}
	block, _ := pem.Decode(input.CSRPem)
	if block == nil {
		http.Error(w, "block was nil", http.StatusInternalServerError)
		return
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	template := &x509.Certificate{
		SerialNumber:       serialNumber,
		Subject:            csr.Subject,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,
		SignatureAlgorithm: x509.SHA256WithRSA,
		DNSNames:           csr.DNSNames,
		IPAddresses:        csr.IPAddresses,
		EmailAddresses:     csr.EmailAddresses,
		URIs:               csr.URIs,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().AddDate(0, 0, int(*input.Validity.Value)),
	}
	cert, err := x509.CreateCertificate(rand.Reader, template, f.caCert.cert, csr.PublicKey, f.caKey.key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	f.signedCertPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})

	output := struct {
		CertificateARN string `json:"CertificateArn,omitempty"`
	}{
		CertificateARN: f.certARN,
	}
	if err := json.NewEncoder(w).Encode(&output); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (f *fakeACMPCA) ServeGetCertificate(w http.ResponseWriter, r *http.Request) {
	input := struct {
		CertificateAuthorityARN string `json:"CertificateAuthorityARN,omitempty"`
		CertificateARN          string `json:"CertificateARN,omitempty"`
	}{}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if input.CertificateAuthorityARN != f.caARN {
		http.Error(w, "unknown CA ARN", http.StatusNotFound)
		return
	}
	if input.CertificateARN != f.certARN {
		http.Error(w, "unknown cert ARN", http.StatusNotFound)
		return
	}
	output := struct {
		Certificate      string `json:"Certificate,omitempty"`
		CertificateChain string `json:"CertificateChain,omitempty"`
	}{
		Certificate:      string(f.signedCertPEM),
		CertificateChain: string(f.caCert.pem),
	}
	if err := json.NewEncoder(w).Encode(&output); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

type keyGeneratorFunc func() (crypto.PrivateKey, error)

func (kgf keyGeneratorFunc) Generate() (crypto.PrivateKey, error) {
	return kgf()
}

type key struct {
	pem []byte
	key *rsa.PrivateKey
}

type cert struct {
	pem  []byte
	cert *x509.Certificate
}

func generateCertAndKey() (*cert, *key, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "Certify Test Cert",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
	if err != nil {
		return nil, nil, err
	}

	k := &key{
		key: priv,
		pem: pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		}),
	}
	crt, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}
	c := &cert{
		cert: crt,
		pem: pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: derBytes,
		}),
	}
	return c, k, nil
}
