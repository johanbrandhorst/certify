package vault_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/spiffe/go-spiffe/uri"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/grpclog"

	"github.com/johanbrandhorst/certify"
	"github.com/johanbrandhorst/certify/issuers/vault"
	"github.com/johanbrandhorst/certify/issuers/vault/proto"
)

//go:generate protoc --go_out=plugins=grpc,paths=source_relative:./ ./proto/test.proto

type otherName struct {
	TypeID asn1.ObjectIdentifier
	Value  string `asn1:"explicit,utf8"`
}

func getOtherNames(cert *x509.Certificate) (otherNames []otherName, err error) {
	for _, ext := range uri.GetExtensionsFromAsn1ObjectIdentifier(cert, uri.OidExtensionSubjectAltName) {
		var altName asn1.RawValue
		_, _ = asn1.Unmarshal(ext.Value, &altName)
		if altName.Class == asn1.ClassUniversal && altName.Tag == asn1.TagSequence {
			data := altName.Bytes
			for len(data) > 0 {
				var alt asn1.RawValue
				data, _ = asn1.Unmarshal(data, &alt)
				if alt.Class == asn1.ClassContextSpecific && alt.Tag == 0 {
					var oName otherName
					_, err = asn1.UnmarshalWithParams(alt.FullBytes, &oName, "tag:0")
					if err != nil {
						return
					}
					otherNames = append(otherNames, oName)
				}
			}
		}
	}

	return otherNames, nil
}

var _ = Describe("Vault Issuer", func() {
	var iss certify.Issuer
	var conf *certify.CertConfig

	BeforeEach(func() {
		iss = &vault.Issuer{
			URL:        vaultTLSConf.URL,
			AuthMethod: vault.ConstantToken(vaultTLSConf.Token),
			Role:       vaultTLSConf.Role,
			TLSConfig: &tls.Config{
				RootCAs: vaultTLSConf.CertPool,
			},
			TimeToLive: time.Minute * 10,
			// Format is "<type_id>;utf8:<value>", where type_id
			// is an ASN.1 object identifier.
			OtherSubjectAlternativeNames: []string{"1.3.6.1.4.1.311.20.2.3;utf8:devops@nope.com"},
		}
		conf = &certify.CertConfig{
			KeyGenerator: keyGeneratorFunc(func() (crypto.PrivateKey, error) {
				return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			}),
		}
	})

	It("issues a certificate", func() {
		cn := "somename.com"

		tlsCert, err := iss.Issue(context.Background(), cn, conf)
		Expect(err).NotTo(HaveOccurred())

		Expect(tlsCert.Leaf).NotTo(BeNil(), "tlsCert.Leaf should be populated by Issue to track expiry")
		Expect(tlsCert.Leaf.Subject.CommonName).To(Equal(cn))

		// Check that chain is included
		Expect(tlsCert.Certificate).To(HaveLen(2))
		caCert, err := x509.ParseCertificate(tlsCert.Certificate[1])
		Expect(err).NotTo(HaveOccurred())
		Expect(caCert.Subject.SerialNumber).To(Equal(tlsCert.Leaf.Issuer.SerialNumber))

		Expect(tlsCert.Leaf.NotBefore).To(BeTemporally("<", time.Now()))
		Expect(tlsCert.Leaf.NotAfter).To(BeTemporally("~", time.Now().Add(iss.(*vault.Issuer).TimeToLive), 5*time.Second))
		Expect(getOtherNames(tlsCert.Leaf)).To(ConsistOf(otherName{
			TypeID: asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}),
			Value:  "devops@nope.com",
		}))
	})

	Context("with no explicit AuthMethod set", func() {
		It("still works", func() {
			cn := "somename.com"

			tlsCert, err := iss.Issue(context.Background(), cn, conf)
			Expect(err).NotTo(HaveOccurred())

			Expect(tlsCert.Leaf).NotTo(BeNil(), "tlsCert.Leaf should be populated by Issue to track expiry")
			Expect(tlsCert.Leaf.Subject.CommonName).To(Equal(cn))

			// Check that chain is included
			Expect(tlsCert.Certificate).To(HaveLen(2))
			caCert, err := x509.ParseCertificate(tlsCert.Certificate[1])
			Expect(err).NotTo(HaveOccurred())
			Expect(caCert.Subject.SerialNumber).To(Equal(tlsCert.Leaf.Issuer.SerialNumber))

			Expect(tlsCert.Leaf.NotBefore).To(BeTemporally("<", time.Now()))
			Expect(tlsCert.Leaf.NotAfter).To(BeTemporally("~", time.Now().Add(iss.(*vault.Issuer).TimeToLive), 5*time.Second))
			Expect(getOtherNames(tlsCert.Leaf)).To(ConsistOf(otherName{
				TypeID: asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}),
				Value:  "devops@nope.com",
			}))
		})
	})

	Context("with URI SANs", func() {
		BeforeEach(func() {
			iss = &vault.Issuer{
				URL:        vaultTLSConf.URL,
				AuthMethod: vault.ConstantToken(vaultTLSConf.Token),
				Role:       vaultTLSConf.RoleURISANs,
				TLSConfig: &tls.Config{
					RootCAs: vaultTLSConf.CertPool,
				},
				TimeToLive:                 time.Minute * 10,
				URISubjectAlternativeNames: []string{"spiffe://hostname/testing"},
			}
		})

		It("issues a certificate", func() {
			cn := "somename.com"

			tlsCert, err := iss.Issue(context.Background(), cn, conf)
			Expect(err).NotTo(HaveOccurred())

			Expect(tlsCert.Leaf).NotTo(BeNil(), "tlsCert.Leaf should be populated by Issue to track expiry")
			Expect(tlsCert.Leaf.Subject.CommonName).To(Equal(cn))

			certURIs, err := uri.GetURINamesFromCertificate(tlsCert.Leaf)
			Expect(err).To(Succeed())
			Expect(certURIs).To(Equal([]string{"spiffe://hostname/testing"}))

			// Check that chain is included
			Expect(tlsCert.Certificate).To(HaveLen(2))
			caCert, err := x509.ParseCertificate(tlsCert.Certificate[1])
			Expect(err).NotTo(HaveOccurred())
			Expect(caCert.Subject.SerialNumber).To(Equal(tlsCert.Leaf.Issuer.SerialNumber))

			Expect(tlsCert.Leaf.NotBefore).To(BeTemporally("<", time.Now()))
			Expect(tlsCert.Leaf.NotAfter).To(BeTemporally("~", time.Now().Add(iss.(*vault.Issuer).TimeToLive), 5*time.Second))
		})
	})

	Context("with one DNS SAN", func() {
		BeforeEach(func() {
			iss = &vault.Issuer{
				URL:        vaultTLSConf.URL,
				AuthMethod: vault.ConstantToken(vaultTLSConf.Token),
				Role:       vaultTLSConf.RoleURISANs,
				TLSConfig: &tls.Config{
					RootCAs: vaultTLSConf.CertPool,
				},
				TimeToLive:              time.Minute * 10,
				SubjectAlternativeNames: []string{"test.example.com"},
			}
		})

		It("issues a certificate", func() {
			cn := "somename.com"

			tlsCert, err := iss.Issue(context.Background(), cn, conf)
			Expect(err).NotTo(HaveOccurred())

			Expect(tlsCert.Leaf).NotTo(BeNil(), "tlsCert.Leaf should be populated by Issue to track expiry")
			Expect(tlsCert.Leaf.Subject.CommonName).To(Equal(cn))

			Expect(tlsCert.Leaf.DNSNames).To(ConsistOf("test.example.com"))

			// Check that chain is included
			Expect(tlsCert.Certificate).To(HaveLen(2))
			caCert, err := x509.ParseCertificate(tlsCert.Certificate[1])
			Expect(err).NotTo(HaveOccurred())
			Expect(caCert.Subject.SerialNumber).To(Equal(tlsCert.Leaf.Issuer.SerialNumber))

			Expect(tlsCert.Leaf.NotBefore).To(BeTemporally("<", time.Now()))
			Expect(tlsCert.Leaf.NotAfter).To(BeTemporally("~", time.Now().Add(iss.(*vault.Issuer).TimeToLive), 5*time.Second))
		})
	})

	Context("with multiple DNS SANs", func() {
		BeforeEach(func() {
			iss = &vault.Issuer{
				URL:        vaultTLSConf.URL,
				AuthMethod: vault.ConstantToken(vaultTLSConf.Token),
				Role:       vaultTLSConf.RoleURISANs,
				TLSConfig: &tls.Config{
					RootCAs: vaultTLSConf.CertPool,
				},
				TimeToLive:              time.Minute * 10,
				SubjectAlternativeNames: []string{"test.example.com", "foobar.example.com"},
			}
		})

		It("issues a certificate", func() {
			cn := "somename.com"

			tlsCert, err := iss.Issue(context.Background(), cn, conf)
			Expect(err).NotTo(HaveOccurred())

			Expect(tlsCert.Leaf).NotTo(BeNil(), "tlsCert.Leaf should be populated by Issue to track expiry")
			Expect(tlsCert.Leaf.Subject.CommonName).To(Equal(cn))

			Expect(tlsCert.Leaf.DNSNames).To(ConsistOf("test.example.com", "foobar.example.com"))

			// Check that chain is included
			Expect(tlsCert.Certificate).To(HaveLen(2))
			caCert, err := x509.ParseCertificate(tlsCert.Certificate[1])
			Expect(err).NotTo(HaveOccurred())
			Expect(caCert.Subject.SerialNumber).To(Equal(tlsCert.Leaf.Issuer.SerialNumber))

			Expect(tlsCert.Leaf.NotBefore).To(BeTemporally("<", time.Now()))
			Expect(tlsCert.Leaf.NotAfter).To(BeTemporally("~", time.Now().Add(iss.(*vault.Issuer).TimeToLive), 5*time.Second))
		})
	})

	Context("with one IP SAN", func() {
		BeforeEach(func() {
			iss = &vault.Issuer{
				URL:        vaultTLSConf.URL,
				AuthMethod: vault.ConstantToken(vaultTLSConf.Token),
				Role:       vaultTLSConf.RoleURISANs,
				TLSConfig: &tls.Config{
					RootCAs: vaultTLSConf.CertPool,
				},
				TimeToLive:                time.Minute * 10,
				IPSubjectAlternativeNames: []string{"127.0.0.1"},
			}
		})

		It("issues a certificate", func() {
			cn := "somename.com"

			tlsCert, err := iss.Issue(context.Background(), cn, conf)
			Expect(err).NotTo(HaveOccurred())

			Expect(tlsCert.Leaf).NotTo(BeNil(), "tlsCert.Leaf should be populated by Issue to track expiry")
			Expect(tlsCert.Leaf.Subject.CommonName).To(Equal(cn))

			Expect(tlsCert.Leaf.IPAddresses).To(HaveLen(1))
			Expect(tlsCert.Leaf.IPAddresses[0].Equal(net.IPv4(127, 0, 0, 1))).To(BeTrue())

			// Check that chain is included
			Expect(tlsCert.Certificate).To(HaveLen(2))
			caCert, err := x509.ParseCertificate(tlsCert.Certificate[1])
			Expect(err).NotTo(HaveOccurred())
			Expect(caCert.Subject.SerialNumber).To(Equal(tlsCert.Leaf.Issuer.SerialNumber))

			Expect(tlsCert.Leaf.NotBefore).To(BeTemporally("<", time.Now()))
			Expect(tlsCert.Leaf.NotAfter).To(BeTemporally("~", time.Now().Add(iss.(*vault.Issuer).TimeToLive), 5*time.Second))
		})
	})

	Context("with a non-standard mount point", func() {
		BeforeEach(func() {
			iss = &vault.Issuer{
				URL:        vaultTLSConf.URL,
				AuthMethod: vault.ConstantToken(vaultTLSConf.Token),
				Mount:      altMount,
				Role:       vaultTLSConf.Role,
				TLSConfig: &tls.Config{
					RootCAs: vaultTLSConf.CertPool,
				},
				TimeToLive: time.Minute * 10,
				// Format is "<type_id>;utf8:<value>", where type_id
				// is an ASN.1 object identifier.
				OtherSubjectAlternativeNames: []string{"1.3.6.1.4.1.311.20.2.3;utf8:devops@nope.com"},
			}
		})

		It("issues a certificate", func() {
			cn := "somename.com"

			tlsCert, err := iss.Issue(context.Background(), cn, conf)
			Expect(err).NotTo(HaveOccurred())

			Expect(tlsCert.Leaf).NotTo(BeNil(), "tlsCert.Leaf should be populated by Issue to track expiry")
			Expect(tlsCert.Leaf.Subject.CommonName).To(Equal(cn))

			// Check that chain is included
			Expect(tlsCert.Certificate).To(HaveLen(2))
			caCert, err := x509.ParseCertificate(tlsCert.Certificate[1])
			Expect(err).NotTo(HaveOccurred())
			Expect(caCert.Subject.SerialNumber).To(Equal(tlsCert.Leaf.Issuer.SerialNumber))

			Expect(tlsCert.Leaf.NotBefore).To(BeTemporally("<", time.Now()))
			Expect(tlsCert.Leaf.NotAfter).To(BeTemporally("~", time.Now().Add(iss.(*vault.Issuer).TimeToLive), 5*time.Second))
			Expect(getOtherNames(tlsCert.Leaf)).To(ConsistOf(otherName{
				TypeID: asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}),
				Value:  "devops@nope.com",
			}))
		})
	})

	Context("when specifying some SANs, IPSANs", func() {
		It("issues a certificate with the SANs and IPSANs", func() {
			conf.SubjectAlternativeNames = []string{"extraname.com", "otherextraname.com"}
			conf.IPSubjectAlternativeNames = []net.IP{net.IPv4(1, 2, 3, 4), net.IPv6loopback}
			cn := "somename.com"

			tlsCert, err := iss.Issue(context.Background(), cn, conf)
			Expect(err).NotTo(HaveOccurred())

			Expect(tlsCert.Leaf).NotTo(BeNil(), "tlsCert.Leaf should be populated by Issue to track expiry")
			Expect(tlsCert.Leaf.Subject.CommonName).To(Equal(cn))
			Expect(tlsCert.Leaf.DNSNames).To(Equal(conf.SubjectAlternativeNames))
			Expect(tlsCert.Leaf.IPAddresses).To(HaveLen(len(conf.IPSubjectAlternativeNames)))
			for i, ip := range tlsCert.Leaf.IPAddresses {
				Expect(ip.Equal(conf.IPSubjectAlternativeNames[i])).To(BeTrue())
			}

			// Check that chain is included
			Expect(tlsCert.Certificate).To(HaveLen(2))
			caCert, err := x509.ParseCertificate(tlsCert.Certificate[1])
			Expect(err).NotTo(HaveOccurred())
			Expect(caCert.Subject.SerialNumber).To(Equal(tlsCert.Leaf.Issuer.SerialNumber))

			Expect(tlsCert.Leaf.NotBefore).To(BeTemporally("<", time.Now()))
			Expect(tlsCert.Leaf.NotAfter).To(BeTemporally("~", time.Now().Add(iss.(*vault.Issuer).TimeToLive), 5*time.Second))
			Expect(getOtherNames(tlsCert.Leaf)).To(ConsistOf(otherName{
				TypeID: asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}),
				Value:  "devops@nope.com",
			}))
		})
	})

	Context("when the TTL is not specified", func() {
		It("issues a certificate with the role TTL", func() {
			iss.(*vault.Issuer).TimeToLive = 0

			cn := "somename.com"

			tlsCert, err := iss.Issue(context.Background(), cn, conf)
			Expect(err).NotTo(HaveOccurred())

			Expect(tlsCert.Leaf).NotTo(BeNil(), "tlsCert.Leaf should be populated by Issue to track expiry")
			Expect(tlsCert.Leaf.Subject.CommonName).To(Equal(cn))

			// Check that chain is included
			Expect(tlsCert.Certificate).To(HaveLen(2))
			caCert, err := x509.ParseCertificate(tlsCert.Certificate[1])
			Expect(err).NotTo(HaveOccurred())
			Expect(caCert.Subject.SerialNumber).To(Equal(tlsCert.Leaf.Issuer.SerialNumber))

			Expect(tlsCert.Leaf.NotBefore).To(BeTemporally("<", time.Now()))
			Expect(tlsCert.Leaf.NotAfter).To(BeTemporally("~", time.Now().Add(defaultTTL), 5*time.Second))
			Expect(getOtherNames(tlsCert.Leaf)).To(ConsistOf(otherName{
				TypeID: asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}),
				Value:  "devops@nope.com",
			}))
		})
	})
})

var _ = Describe("Vault HTTP Issuer", func() {
	var iss certify.Issuer
	var conf *certify.CertConfig

	BeforeEach(func() {
		iss = &vault.Issuer{
			URL:        vaultConf.URL,
			AuthMethod: vault.ConstantToken(vaultTLSConf.Token),
			Role:       vaultConf.Role,
			TimeToLive: time.Minute * 10,
			// Format is "<type_id>;utf8:<value>", where type_id
			// is an ASN.1 object identifier.
			OtherSubjectAlternativeNames: []string{"1.3.6.1.4.1.311.20.2.3;utf8:devops@nope.com"},
		}
		conf = &certify.CertConfig{
			KeyGenerator: keyGeneratorFunc(func() (crypto.PrivateKey, error) {
				return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			}),
		}
	})

	It("issues a certificate", func() {
		cn := "somename.com"

		tlsCert, err := iss.Issue(context.Background(), cn, conf)
		Expect(err).NotTo(HaveOccurred())

		Expect(tlsCert.Leaf).NotTo(BeNil(), "tlsCert.Leaf should be populated by Issue to track expiry")
		Expect(tlsCert.Leaf.Subject.CommonName).To(Equal(cn))

		// Check that chain is included
		Expect(tlsCert.Certificate).To(HaveLen(2))
		caCert, err := x509.ParseCertificate(tlsCert.Certificate[1])
		Expect(err).NotTo(HaveOccurred())
		Expect(caCert.Subject.SerialNumber).To(Equal(tlsCert.Leaf.Issuer.SerialNumber))

		Expect(tlsCert.Leaf.NotBefore).To(BeTemporally("<", time.Now()))
		Expect(tlsCert.Leaf.NotAfter).To(BeTemporally("~", time.Now().Add(iss.(*vault.Issuer).TimeToLive), 5*time.Second))
		Expect(getOtherNames(tlsCert.Leaf)).To(ConsistOf(otherName{
			TypeID: asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}),
			Value:  "devops@nope.com",
		}))
	})

	Context("when specifying some SANs, IPSANs", func() {
		It("issues a certificate with the SANs and IPSANs", func() {
			conf.SubjectAlternativeNames = []string{"extraname.com", "otherextraname.com"}
			conf.IPSubjectAlternativeNames = []net.IP{net.IPv4(1, 2, 3, 4), net.IPv6loopback}
			cn := "somename.com"

			tlsCert, err := iss.Issue(context.Background(), cn, conf)
			Expect(err).NotTo(HaveOccurred())

			Expect(tlsCert.Leaf).NotTo(BeNil(), "tlsCert.Leaf should be populated by Issue to track expiry")
			Expect(tlsCert.Leaf.Subject.CommonName).To(Equal(cn))
			Expect(tlsCert.Leaf.DNSNames).To(Equal(conf.SubjectAlternativeNames))
			Expect(tlsCert.Leaf.IPAddresses).To(HaveLen(len(conf.IPSubjectAlternativeNames)))
			for i, ip := range tlsCert.Leaf.IPAddresses {
				Expect(ip.Equal(conf.IPSubjectAlternativeNames[i])).To(BeTrue())
			}

			// Check that chain is included
			Expect(tlsCert.Certificate).To(HaveLen(2))
			caCert, err := x509.ParseCertificate(tlsCert.Certificate[1])
			Expect(err).NotTo(HaveOccurred())
			Expect(caCert.Subject.SerialNumber).To(Equal(tlsCert.Leaf.Issuer.SerialNumber))

			Expect(tlsCert.Leaf.NotBefore).To(BeTemporally("<", time.Now()))
			Expect(tlsCert.Leaf.NotAfter).To(BeTemporally("~", time.Now().Add(iss.(*vault.Issuer).TimeToLive), 5*time.Second))
			Expect(getOtherNames(tlsCert.Leaf)).To(ConsistOf(otherName{
				TypeID: asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}),
				Value:  "devops@nope.com",
			}))
		})
	})

	Context("when the TTL is not specified", func() {
		It("issues a certificate with the role TTL", func() {
			iss.(*vault.Issuer).TimeToLive = 0

			cn := "somename.com"

			tlsCert, err := iss.Issue(context.Background(), cn, conf)
			Expect(err).NotTo(HaveOccurred())

			Expect(tlsCert.Leaf).NotTo(BeNil(), "tlsCert.Leaf should be populated by Issue to track expiry")
			Expect(tlsCert.Leaf.Subject.CommonName).To(Equal(cn))

			// Check that chain is included
			Expect(tlsCert.Certificate).To(HaveLen(2))
			caCert, err := x509.ParseCertificate(tlsCert.Certificate[1])
			Expect(err).NotTo(HaveOccurred())
			Expect(caCert.Subject.SerialNumber).To(Equal(tlsCert.Leaf.Issuer.SerialNumber))

			Expect(tlsCert.Leaf.NotBefore).To(BeTemporally("<", time.Now()))
			Expect(tlsCert.Leaf.NotAfter).To(BeTemporally("~", time.Now().Add(defaultTTL), 5*time.Second))
			Expect(getOtherNames(tlsCert.Leaf)).To(ConsistOf(otherName{
				TypeID: asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}),
				Value:  "devops@nope.com",
			}))
		})
	})
})

var _ = Describe("Using a pre-created client", func() {
	It("issues a certificate", func() {
		vConf := api.DefaultConfig()
		vConf.HttpClient.Transport.(*http.Transport).TLSClientConfig = &tls.Config{
			RootCAs: vaultTLSConf.CertPool,
		}

		vConf.Address = vaultTLSConf.URL.String()
		cli, err := api.NewClient(vConf)
		Expect(err).To(Succeed())

		cli.SetToken(vaultTLSConf.Token)
		iss := vault.FromClient(cli, vaultTLSConf.Role)
		iss.TimeToLive = 10 * time.Minute

		conf := &certify.CertConfig{
			KeyGenerator: keyGeneratorFunc(func() (crypto.PrivateKey, error) {
				return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			}),
		}
		cn := "somename.com"

		tlsCert, err := iss.Issue(context.Background(), cn, conf)
		Expect(err).NotTo(HaveOccurred())

		Expect(tlsCert.Leaf).NotTo(BeNil(), "tlsCert.Leaf should be populated by Issue to track expiry")
		Expect(tlsCert.Leaf.Subject.CommonName).To(Equal(cn))

		// Check that chain is included
		Expect(tlsCert.Certificate).To(HaveLen(2))
		caCert, err := x509.ParseCertificate(tlsCert.Certificate[1])
		Expect(err).NotTo(HaveOccurred())
		Expect(caCert.Subject.SerialNumber).To(Equal(tlsCert.Leaf.Issuer.SerialNumber))

		Expect(tlsCert.Leaf.NotBefore).To(BeTemporally("<", time.Now()))
		Expect(tlsCert.Leaf.NotAfter).To(BeTemporally("~", time.Now().Add(iss.TimeToLive), 5*time.Second))
	})
})

var _ = Describe("When an AuthMethod is not explicitly set", func() {
	It("still works", func() {
		iss := &vault.Issuer{
			URL:   vaultTLSConf.URL,
			Token: vaultTLSConf.Token,
			Role:  vaultTLSConf.Role,
			TLSConfig: &tls.Config{
				RootCAs: vaultTLSConf.CertPool,
			},
			TimeToLive: time.Minute * 10,
		}
		conf := &certify.CertConfig{
			KeyGenerator: keyGeneratorFunc(func() (crypto.PrivateKey, error) {
				return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			}),
		}
		cn := "somename.com"

		tlsCert, err := iss.Issue(context.Background(), cn, conf)
		Expect(err).NotTo(HaveOccurred())

		Expect(tlsCert.Leaf).NotTo(BeNil(), "tlsCert.Leaf should be populated by Issue to track expiry")
		Expect(tlsCert.Leaf.Subject.CommonName).To(Equal(cn))

		// Check that chain is included
		Expect(tlsCert.Certificate).To(HaveLen(2))
		caCert, err := x509.ParseCertificate(tlsCert.Certificate[1])
		Expect(err).NotTo(HaveOccurred())
		Expect(caCert.Subject.SerialNumber).To(Equal(tlsCert.Leaf.Issuer.SerialNumber))

		Expect(tlsCert.Leaf.NotBefore).To(BeTemporally("<", time.Now()))
		Expect(tlsCert.Leaf.NotAfter).To(BeTemporally("~", time.Now().Add(iss.TimeToLive), 5*time.Second))
	})
})

var _ = Describe("When using RenewingToken", func() {
	It("renews the token when it is within the renewal period", func() {
		vConf := api.DefaultConfig()
		vConf.HttpClient.Transport.(*http.Transport).TLSClientConfig = &tls.Config{
			RootCAs: vaultTLSConf.CertPool,
		}
		vConf.Address = vaultTLSConf.URL.String()
		cli, err := api.NewClient(vConf)
		Expect(err).To(Succeed())

		cli.SetToken(vaultTLSConf.Token)

		ttl := time.Minute
		expiry := time.Now().Add(ttl)

		opts := &api.TokenCreateRequest{
			TTL:       ttl.String(),
			Renewable: func() *bool { t := true; return &t }(),
		}
		tok, err := cli.Auth().Token().Create(opts)
		Expect(err).To(Succeed())

		tokTTL, err := tok.TokenTTL()
		Expect(err).To(Succeed())
		Expect(tokTTL).To(BeNumerically("~", time.Until(expiry), time.Second))

		it := tok.Auth.ClientToken
		rt := &vault.RenewingToken{
			Initial:     it,
			RenewBefore: time.Hour,
			TimeToLive:  ttl, // Should renew immediately, since TTL < RenewBefore
		}
		defer func() {
			Expect(rt.Close()).To(Succeed())
		}()

		iss := &vault.Issuer{
			URL:        vaultTLSConf.URL,
			AuthMethod: rt,
			Role:       vaultTLSConf.Role,
			TLSConfig: &tls.Config{
				RootCAs: vaultTLSConf.CertPool,
			},
			TimeToLive: time.Minute * 10,
		}
		conf := &certify.CertConfig{
			KeyGenerator: keyGeneratorFunc(func() (crypto.PrivateKey, error) {
				return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			}),
		}
		cn := "somename.com"

		_, err = iss.Issue(context.Background(), cn, conf)
		Expect(err).To(Succeed())

		time.Sleep(2 * time.Second) // Should cause token to be renewed in the background.

		_, err = iss.Issue(context.Background(), cn, conf)
		Expect(err).To(Succeed())

		newTok, err := cli.Auth().Token().Lookup(it)
		Expect(err).To(Succeed())

		newTTL, err := newTok.TokenTTL()
		Expect(err).To(Succeed())

		// Assert that the token now has a new expiry
		Expect(time.Now().Add(newTTL)).To(BeTemporally(">", expiry, time.Second))
	})
})

type keyGeneratorFunc func() (crypto.PrivateKey, error)

func (kgf keyGeneratorFunc) Generate() (crypto.PrivateKey, error) {
	return kgf()
}

type backend struct{}

func (_ backend) Ping(_ context.Context, _ *proto.Void) (*proto.Void, error) {
	return new(proto.Void), nil
}

var _ = Describe("gRPC Test", func() {
	Context("when using mutual TLS authentication", func() {
		var cb *certify.Certify
		addr := "localhost:0"
		var srv *grpc.Server
		var cc *grpc.ClientConn

		AfterEach(func() {
			if srv != nil {
				srv.GracefulStop()
			}
			if cc != nil {
				Expect(cc.Close()).To(Succeed())
			}
		})

		It("allows client and server to talk to each other", func() {
			var lis net.Listener
			var cli proto.TestClient
			By("Creating the Certify", func() {
				cb = &certify.Certify{
					CommonName: "Certify",
					Issuer: &vault.Issuer{
						URL:        vaultTLSConf.URL,
						AuthMethod: vault.ConstantToken(vaultTLSConf.Token),
						Role:       vaultTLSConf.Role,
						TLSConfig: &tls.Config{
							RootCAs: vaultTLSConf.CertPool,
						},
					},
					Cache:       certify.NewMemCache(),
					RenewBefore: time.Hour,
				}
			})

			By("Starting the gRPC Server", func() {
				var err error

				grpclog.SetLoggerV2(grpclog.NewLoggerV2(GinkgoWriter, ioutil.Discard, ioutil.Discard))
				lis, err = net.Listen("tcp", addr)
				Expect(err).To(Succeed())

				cp := x509.NewCertPool()
				cp.AddCert(vaultTLSConf.CA)
				tlsConfig := &tls.Config{
					GetCertificate: cb.GetCertificate,
					ClientCAs:      cp,
					ClientAuth:     tls.RequireAndVerifyClientCert,
				}

				srv = grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
				proto.RegisterTestServer(srv, &backend{})

				go func() {
					_ = srv.Serve(lis)
				}()
			})

			By("Creating the client", func() {
				cp := x509.NewCertPool()
				cp.AddCert(vaultTLSConf.CA)
				tlsConfig := &tls.Config{
					GetClientCertificate: cb.GetClientCertificate,
					RootCAs:              cp,
					ServerName:           strings.Split(addr, ":")[0],
				}
				var err error
				cc, err = grpc.Dial(lis.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
				Expect(err).To(Succeed())

				cli = proto.NewTestClient(cc)
			})

			_, err := cli.Ping(context.Background(), new(proto.Void))
			Expect(err).To(Succeed())
		})
	})
})
