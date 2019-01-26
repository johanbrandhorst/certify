package cfssl_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"

	"github.com/cloudflare/cfssl/auth"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/johanbrandhorst/certify"
	"github.com/johanbrandhorst/certify/issuers/cfssl"
)

var _ = Describe("CFSSL Issuer", func() {
	var iss certify.Issuer

	BeforeEach(func() {
		iss = &cfssl.Issuer{
			URL: cfsslConf.URL,
			TLSConfig: &tls.Config{
				RootCAs:            cfsslConf.CertPool,
				InsecureSkipVerify: true,
			},
		}
	})

	It("issues a certificate", func() {
		cn := "somename.com"

		tlsCert, err := iss.Issue(context.Background(), cn, nil)
		Expect(err).NotTo(HaveOccurred())

		Expect(tlsCert.Leaf).NotTo(BeNil(), "tlsCert.Leaf should be populated by Issue to track expiry")
		Expect(tlsCert.Leaf.Subject.CommonName).To(Equal(cn))

		// Check that chain is included
		Expect(tlsCert.Certificate).To(HaveLen(2))
		caCert, err := x509.ParseCertificate(tlsCert.Certificate[1])
		Expect(err).NotTo(HaveOccurred())
		Expect(caCert.Subject.SerialNumber).To(Equal(tlsCert.Leaf.Issuer.SerialNumber))
	})

	Context("when specifying some SANs, IPSANs", func() {
		It("issues a certificate with the SANs and IPSANs", func() {
			conf := &certify.CertConfig{
				SubjectAlternativeNames:   []string{"extraname.com", "otherextraname.com"},
				IPSubjectAlternativeNames: []net.IP{net.IPv4(1, 2, 3, 4), net.IPv6loopback},
			}
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
		})
	})
})

var _ = Describe("Authenticated CFSSL Issuer", func() {
	var iss certify.Issuer

	BeforeEach(func() {
		st, err := auth.New(cfsslConf.AuthKey, nil)
		Expect(err).To(Succeed())
		iss = &cfssl.Issuer{
			URL: cfsslConf.URL,
			TLSConfig: &tls.Config{
				RootCAs:            cfsslConf.CertPool,
				InsecureSkipVerify: true,
			},
			Auth:    st,
			Profile: cfsslConf.Profile,
		}
	})

	It("issues a certificate", func() {
		cn := "somename.com"

		tlsCert, err := iss.Issue(context.Background(), cn, nil)
		Expect(err).NotTo(HaveOccurred())

		Expect(tlsCert.Leaf).NotTo(BeNil(), "tlsCert.Leaf should be populated by Issue to track expiry")
		Expect(tlsCert.Leaf.Subject.CommonName).To(Equal(cn))

		// Check that chain is included
		Expect(tlsCert.Certificate).To(HaveLen(2))
		caCert, err := x509.ParseCertificate(tlsCert.Certificate[1])
		Expect(err).NotTo(HaveOccurred())
		Expect(caCert.Subject.SerialNumber).To(Equal(tlsCert.Leaf.Issuer.SerialNumber))
	})

	Context("when specifying some SANs, IPSANs", func() {
		It("issues a certificate with the SANs and IPSANs", func() {
			conf := &certify.CertConfig{
				SubjectAlternativeNames:   []string{"extraname.com", "otherextraname.com"},
				IPSubjectAlternativeNames: []net.IP{net.IPv4(1, 2, 3, 4), net.IPv6loopback},
			}
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
		})
	})
})
