package aws_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"time"

	api "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"

	"github.com/johanbrandhorst/certify"
	"github.com/johanbrandhorst/certify/internal/certs"
	"github.com/johanbrandhorst/certify/issuers/aws"
	"github.com/johanbrandhorst/certify/issuers/aws/mocks"
)

//go:generate moq -out mocks/client.mock.go -pkg mocks ../../vendor/github.com/aws/aws-sdk-go-v2/service/acmpca/acmpcaiface ACMPCAAPI

var _ = Describe("AWS Issuer", func() {
	It("issues a certificate", func() {
		caARN := "someARN"
		certARN := "anotherARN"
		caCert, caKey, err := certs.GenerateCertAndKey()
		Expect(err).To(Succeed())
		client := &mocks.ACMPCAAPIMock{}
		iss := &aws.Issuer{
			CertificateAuthorityARN: caARN,
			Client:                  client,
			TimeToLive:              25,
		}
		var signedCert []byte
		client.IssueCertificateRequestFunc = func(in1 *acmpca.IssueCertificateInput) acmpca.IssueCertificateRequest {
			Expect(in1.CertificateAuthorityArn).To(PointTo(Equal(caARN)))
			Expect(in1.Validity.Value).To(PointTo(BeEquivalentTo(iss.TimeToLive)))
			b, _ := pem.Decode(in1.Csr)
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
				NotAfter:           time.Now().AddDate(0, 0, int(*in1.Validity.Value)),
			}
			crt, err := x509.CreateCertificate(rand.Reader, template, caCert.Cert, csr.PublicKey, caKey.Key)
			Expect(err).NotTo(HaveOccurred())
			signedCert = pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: crt,
			})
			hl := api.HandlerList{}
			hl.PushBackNamed(api.NamedHandler{
				Name: "Send",
				Fn: func(in *api.Request) {
					in.Data = &acmpca.IssueCertificateOutput{
						CertificateArn: api.String(certARN),
					}
				},
			})
			return acmpca.IssueCertificateRequest{
				Request: &api.Request{
					Handlers: api.Handlers{
						Send: hl,
					},
				},
				Input: in1,
			}
		}
		client.GetCertificateRequestFunc = func(in1 *acmpca.GetCertificateInput) acmpca.GetCertificateRequest {
			Expect(in1.CertificateArn).To(PointTo(Equal(certARN)))
			Expect(in1.CertificateAuthorityArn).To(PointTo(Equal(caARN)))
			hl := api.HandlerList{}
			hl.PushBackNamed(api.NamedHandler{
				Name: "Send",
				Fn: func(in *api.Request) {
					in.Data = &acmpca.GetCertificateOutput{
						Certificate:      api.String(string(signedCert)),
						CertificateChain: api.String(string(caCert.PEM)),
					}
				},
			})
			return acmpca.GetCertificateRequest{
				Request: &api.Request{
					Handlers: api.Handlers{
						Send: hl,
					},
				},
				Input: in1,
			}
		}
		client.GetCertificateAuthorityCertificateRequestFunc = func(in1 *acmpca.GetCertificateAuthorityCertificateInput) acmpca.GetCertificateAuthorityCertificateRequest {
			Expect(in1.CertificateAuthorityArn).To(PointTo(Equal(caARN)))
			hl := api.HandlerList{}
			hl.PushBackNamed(api.NamedHandler{
				Name: "Send",
				Fn: func(in *api.Request) {
					in.Data = &acmpca.GetCertificateAuthorityCertificateOutput{
						Certificate:      api.String(string(caCert.PEM)),
						CertificateChain: api.String(string(caCert.PEM)),
					}
				},
			})
			return acmpca.GetCertificateAuthorityCertificateRequest{
				Request: &api.Request{
					Handlers: api.Handlers{
						Send: hl,
					},
				},
				Input: in1,
			}
		}
		client.WaitUntilCertificateIssuedWithContextFunc = func(in1 api.Context, in2 *acmpca.GetCertificateInput, in3 ...api.WaiterOption) error {
			Expect(in2.CertificateAuthorityArn).To(PointTo(Equal(caARN)))
			Expect(in2.CertificateArn).To(PointTo(Equal(certARN)))
			hl := api.HandlerList{}
			hl.PushBackNamed(api.NamedHandler{
				Name: "Send",
				Fn: func(in *api.Request) {
					in.Data = &acmpca.GetCertificateAuthorityCertificateOutput{
						Certificate:      api.String(string(caCert.PEM)),
						CertificateChain: api.String(string(caCert.PEM)),
					}
				},
			})
			return nil
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
		crt, err := x509.ParseCertificate(tlsCert.Certificate[1])
		Expect(err).NotTo(HaveOccurred())
		Expect(crt.Subject.SerialNumber).To(Equal(tlsCert.Leaf.Issuer.SerialNumber))

		Expect(tlsCert.Leaf.NotBefore).To(BeTemporally("<", time.Now()))
		Expect(tlsCert.Leaf.NotAfter).To(BeTemporally("~", time.Now().AddDate(0, 0, iss.TimeToLive), 5*time.Second))
	})
})

type keyGeneratorFunc func() (crypto.PrivateKey, error)

func (kgf keyGeneratorFunc) Generate() (crypto.PrivateKey, error) {
	return kgf()
}
