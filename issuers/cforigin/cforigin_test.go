package cforigin_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/cloudflare/cloudflare-go"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/johanbrandhorst/certify"
	"github.com/johanbrandhorst/certify/internal/certs"
	"github.com/johanbrandhorst/certify/issuers/cforigin"
)

var _ = Describe("Cloudflare Origin Issuer", func() {
	It("issues a certificate", func() {
		api, err := cloudflare.New("someKey", "someEmail", cloudflare.HTTPClient(cli))
		Expect(err).NotTo(HaveOccurred())
		api.BaseURL = srv.URL

		cn := "somename.com"
		conf := &certify.CertConfig{
			KeyGenerator: keyGeneratorFunc(func() (crypto.PrivateKey, error) {
				return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			}),
		}

		caCert, caKey, err := certs.GenerateCertAndKey()

		handler = func(req cloudflare.OriginCACertificate) (cloudflare.OriginCACertificate, error) {
			b, _ := pem.Decode([]byte(req.CSR))
			csr, err := x509.ParseCertificateRequest(b.Bytes)
			Expect(err).NotTo(HaveOccurred())
			serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
			serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
			Expect(err).NotTo(HaveOccurred())
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
				NotAfter:           time.Now().AddDate(0, 0, int(req.RequestValidity)),
			}
			crt, err := x509.CreateCertificate(rand.Reader, template, caCert.Cert, csr.PublicKey, caKey.Key)
			Expect(err).NotTo(HaveOccurred())
			signedCert := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: crt,
			})
			return cloudflare.OriginCACertificate{
				Certificate: string(signedCert),
				ExpiresOn:   template.NotAfter,
				RequestType: "origin-rsa",
			}, nil
		}

		iss, err := cforigin.FromClient(api)
		Expect(err).NotTo(HaveOccurred())

		tlsCert, err := iss.Issue(context.Background(), cn, conf)
		Expect(err).NotTo(HaveOccurred())

		Expect(tlsCert.Leaf).NotTo(BeNil(), "tlsCert.Leaf should be populated by Issue to track expiry")
		Expect(tlsCert.Leaf.Subject.CommonName).To(Equal(cn))

		// Check that chain is included
		Expect(tlsCert.Certificate).To(HaveLen(2))
		cfCert, err := x509.ParseCertificate(tlsCert.Certificate[1])
		Expect(err).NotTo(HaveOccurred())
		Expect(cfCert.Subject.Organization).To(ConsistOf("CloudFlare, Inc."))
		Expect(cfCert.PublicKey).To(BeAssignableToTypeOf(&rsa.PublicKey{}))
	})

	Context("when the request type is origin-ecc", func() {
		It("adds the cloudflare ECC root to the chain", func() {
			api, err := cloudflare.New("someKey", "someEmail", cloudflare.HTTPClient(cli))
			Expect(err).NotTo(HaveOccurred())
			api.BaseURL = srv.URL

			cn := "somename.com"
			conf := &certify.CertConfig{
				KeyGenerator: keyGeneratorFunc(func() (crypto.PrivateKey, error) {
					return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				}),
			}

			caCert, caKey, err := certs.GenerateCertAndKey()

			handler = func(req cloudflare.OriginCACertificate) (cloudflare.OriginCACertificate, error) {
				b, _ := pem.Decode([]byte(req.CSR))
				csr, err := x509.ParseCertificateRequest(b.Bytes)
				Expect(err).NotTo(HaveOccurred())
				serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
				serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
				Expect(err).NotTo(HaveOccurred())
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
					NotAfter:           time.Now().AddDate(0, 0, int(req.RequestValidity)),
				}
				crt, err := x509.CreateCertificate(rand.Reader, template, caCert.Cert, csr.PublicKey, caKey.Key)
				Expect(err).NotTo(HaveOccurred())
				signedCert := pem.EncodeToMemory(&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: crt,
				})
				return cloudflare.OriginCACertificate{
					Certificate: string(signedCert),
					ExpiresOn:   template.NotAfter,
					RequestType: "origin-ecc",
				}, nil
			}

			iss, err := cforigin.FromClient(api)
			Expect(err).NotTo(HaveOccurred())

			tlsCert, err := iss.Issue(context.Background(), cn, conf)
			Expect(err).NotTo(HaveOccurred())

			Expect(tlsCert.Leaf).NotTo(BeNil(), "tlsCert.Leaf should be populated by Issue to track expiry")
			Expect(tlsCert.Leaf.Subject.CommonName).To(Equal(cn))

			// Check that chain is included
			Expect(tlsCert.Certificate).To(HaveLen(2))
			cfCert, err := x509.ParseCertificate(tlsCert.Certificate[1])
			Expect(err).NotTo(HaveOccurred())
			Expect(cfCert.Subject.Organization).To(ConsistOf("CloudFlare, Inc."))
			Expect(cfCert.PublicKey).To(BeAssignableToTypeOf(&ecdsa.PublicKey{}))
		})
	})
})

type keyGeneratorFunc func() (crypto.PrivateKey, error)

func (kgf keyGeneratorFunc) Generate() (crypto.PrivateKey, error) {
	return kgf()
}
