package csr_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/johanbrandhorst/certify"
	"github.com/johanbrandhorst/certify/internal/csr"
)

var _ = Describe("FromCertConfig", func() {
	It("Generates a CSR and a Key", func() {
		conf := &certify.CertConfig{
			SubjectAlternativeNames:   []string{"extraname.com"},
			IPSubjectAlternativeNames: []net.IP{net.IPv4(1, 2, 3, 4)},
			KeyGenerator: keyGeneratorFunc(func() (crypto.PrivateKey, error) {
				return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			}),
		}
		csrPEM, keyPEM, err := csr.FromCertConfig("myserver.com", conf)
		Expect(err).To(Succeed())

		csrBlock, _ := pem.Decode(csrPEM)
		csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
		Expect(err).To(Succeed())
		Expect(csr.PublicKeyAlgorithm).To(Equal(x509.ECDSA))
		Expect(csr.PublicKey).To(BeAssignableToTypeOf(&ecdsa.PublicKey{}))
		Expect(csr.Subject.CommonName).To(Equal("myserver.com"))
		Expect(csr.DNSNames).To(Equal(conf.SubjectAlternativeNames))
		for i, ip := range csr.IPAddresses {
			Expect(ip.Equal(conf.IPSubjectAlternativeNames[i])).To(BeTrue())
		}

		keyBlock, _ := pem.Decode(keyPEM)
		key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
		Expect(err).To(Succeed())
		Expect(key.Params().BitSize).To(Equal(256))
	})
})

type keyGeneratorFunc func() (crypto.PrivateKey, error)

func (kgf keyGeneratorFunc) Generate() (crypto.PrivateKey, error) {
	return kgf()
}
