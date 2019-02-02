package vault_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/grpclog"

	"github.com/johanbrandhorst/certify"
	"github.com/johanbrandhorst/certify/issuers/vault"
	"github.com/johanbrandhorst/certify/issuers/vault/proto"
)

//go:generate protoc --go_out=plugins=grpc:./ ./proto/test.proto

var _ = Describe("Vault Issuer", func() {
	var iss certify.Issuer

	BeforeEach(func() {
		iss = &vault.Issuer{
			URL:   vaultTLSConf.URL,
			Token: vaultTLSConf.Token,
			Role:  vaultTLSConf.Role,
			TLSConfig: &tls.Config{
				RootCAs: vaultTLSConf.CertPool,
			},
			TimeToLive: time.Minute * 10,
			// No idea how to format this. Copied from
			// https://github.com/hashicorp/vault/blob/abb8b41331573efdbfad3505b7ad2c81ef6d19c0/builtin/logical/pki/backend_test.go#L3135
			OtherSubjectAlternativeNames: []string{"1.3.6.1.4.1.311.20.2.3;utf8:devops@nope.com"},
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

		Expect(tlsCert.Leaf.NotBefore).To(BeTemporally("<", time.Now()))
		Expect(tlsCert.Leaf.NotAfter).To(BeTemporally("~", time.Now().Add(iss.(*vault.Issuer).TimeToLive), 5*time.Second))
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

			Expect(tlsCert.Leaf.NotBefore).To(BeTemporally("<", time.Now()))
			Expect(tlsCert.Leaf.NotAfter).To(BeTemporally("~", time.Now().Add(iss.(*vault.Issuer).TimeToLive), 5*time.Second))
		})
	})

	Context("when the TTL is not specified", func() {
		It("issues a certificate with the role TTL", func() {
			iss.(*vault.Issuer).TimeToLive = 0

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

			Expect(tlsCert.Leaf.NotBefore).To(BeTemporally("<", time.Now()))
			Expect(tlsCert.Leaf.NotAfter).To(BeTemporally("~", time.Now().Add(defaultTTL), 5*time.Second))
		})
	})
})

var _ = Describe("Vault HTTP Issuer", func() {
	var iss certify.Issuer

	BeforeEach(func() {
		iss = &vault.Issuer{
			URL:   vaultConf.URL,
			Token: vaultConf.Token,
			Role:  vaultConf.Role,
			TimeToLive: time.Minute * 10,
			// No idea how to format this. Copied from
			// https://github.com/hashicorp/vault/blob/abb8b41331573efdbfad3505b7ad2c81ef6d19c0/builtin/logical/pki/backend_test.go#L3135
			OtherSubjectAlternativeNames: []string{"1.3.6.1.4.1.311.20.2.3;utf8:devops@nope.com"},
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

		Expect(tlsCert.Leaf.NotBefore).To(BeTemporally("<", time.Now()))
		Expect(tlsCert.Leaf.NotAfter).To(BeTemporally("~", time.Now().Add(iss.(*vault.Issuer).TimeToLive), 5*time.Second))
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

			Expect(tlsCert.Leaf.NotBefore).To(BeTemporally("<", time.Now()))
			Expect(tlsCert.Leaf.NotAfter).To(BeTemporally("~", time.Now().Add(iss.(*vault.Issuer).TimeToLive), 5*time.Second))
		})
	})

	Context("when the TTL is not specified", func() {
		It("issues a certificate with the role TTL", func() {
			iss.(*vault.Issuer).TimeToLive = 0

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

			Expect(tlsCert.Leaf.NotBefore).To(BeTemporally("<", time.Now()))
			Expect(tlsCert.Leaf.NotAfter).To(BeTemporally("~", time.Now().Add(defaultTTL), 5*time.Second))
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

		Expect(tlsCert.Leaf.NotBefore).To(BeTemporally("<", time.Now()))
		Expect(tlsCert.Leaf.NotAfter).To(BeTemporally("~", time.Now().Add(iss.TimeToLive), 5*time.Second))
	})
})

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
						URL:   vaultTLSConf.URL,
						Token: vaultTLSConf.Token,
						Role:  vaultTLSConf.Role,
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
