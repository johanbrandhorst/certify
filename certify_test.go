package certify_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/cfssl/auth"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/grpclog"

	"github.com/johanbrandhorst/certify"
	"github.com/johanbrandhorst/certify/issuers/cfssl"
	"github.com/johanbrandhorst/certify/issuers/vault"
	"github.com/johanbrandhorst/certify/mocks"
	"github.com/johanbrandhorst/certify/proto"
)

//go:generate protoc --go_out=plugins=grpc:./ ./proto/test.proto
//go:generate moq -out mocks/issuer.mock.go -pkg mocks . Issuer

var _ = Describe("Issuers", func() {
	issuers := []struct {
		Type     string
		IssuerFn func() certify.Issuer
	}{
		{Type: "Vault", IssuerFn: func() certify.Issuer {
			return &vault.Issuer{
				URL:   vaultConf.URL,
				Token: vaultConf.Token,
				Role:  vaultConf.Role,
				TLSConfig: &tls.Config{
					RootCAs: vaultConf.CertPool,
				},
				TimeToLive: time.Minute * 10,
				// No idea how to format this. Copied from
				// https://github.com/hashicorp/vault/blob/abb8b41331573efdbfad3505b7ad2c81ef6d19c0/builtin/logical/pki/backend_test.go#L3135
				OtherSubjectAlternativeNames: []string{"1.3.6.1.4.1.311.20.2.3;utf8:devops@nope.com"},
			}
		}},
		{Type: "CFSSL", IssuerFn: func() certify.Issuer {
			return &cfssl.Issuer{
				URL: cfsslConf.URL,
				TLSConfig: &tls.Config{
					RootCAs:            cfsslConf.CertPool,
					InsecureSkipVerify: true,
				},
			}
		}},
		{Type: "authenticated CFSSL", IssuerFn: func() certify.Issuer {
			st, err := auth.New(cfsslConf.AuthKey, nil)
			Expect(err).To(Succeed())
			return &cfssl.Issuer{
				URL: cfsslConf.URL,
				TLSConfig: &tls.Config{
					RootCAs:            cfsslConf.CertPool,
					InsecureSkipVerify: true,
				},
				Auth:    st,
				Profile: cfsslConf.Profile,
			}
		}},
	}

	for _, issuer := range issuers {
		issuer := issuer
		var iss certify.Issuer

		BeforeEach(func() {
			iss = issuer.IssuerFn()
		})

		Context("when using "+issuer.Type, func() {
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

				if vIss, ok := iss.(*vault.Issuer); ok {
					Expect(tlsCert.Leaf.NotBefore).To(BeTemporally("<", time.Now()))
					Expect(tlsCert.Leaf.NotAfter).To(BeTemporally("~", time.Now().Add(vIss.TimeToLive), 5*time.Second))
				}
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

					if vIss, ok := iss.(*vault.Issuer); ok {
						Expect(tlsCert.Leaf.NotBefore).To(BeTemporally("<", time.Now()))
						Expect(tlsCert.Leaf.NotAfter).To(BeTemporally("~", time.Now().Add(vIss.TimeToLive), 5*time.Second))
					}
				})
			})
		})
	}
})

var _ = Describe("Caches", func() {
	// Note: this setup step doesn't clean
	// up this directory properly after running.
	mustMakeTempDir := func() string {
		n, err := ioutil.TempDir("", "")
		if err != nil {
			panic(err)
		}
		return n
	}

	caches := []struct {
		Type  string
		Cache certify.Cache
	}{
		{Type: "MemCache", Cache: certify.NewMemCache()},
		{Type: "DirCache", Cache: certify.DirCache(mustMakeTempDir())},
	}

	for _, cache := range caches {
		c := cache
		Context("when using "+c.Type, func() {
			Context("after putting in a certificate", func() {
				It("allows a user to get and delete it", func() {
					cert := &tls.Certificate{
						Leaf: &x509.Certificate{
							IsCA: true,
						},
					}
					Expect(c.Cache.Put(context.Background(), "key1", cert)).To(Succeed())
					Expect(c.Cache.Get(context.Background(), "key1")).To(Equal(cert))
					Expect(c.Cache.Delete(context.Background(), "key1")).To(Succeed())
					_, err := c.Cache.Get(context.Background(), "key1")
					Expect(err).To(Equal(certify.ErrCacheMiss))
				})
			})

			Context("when getting a key that doesn't exist", func() {
				It("returns ErrCacheMiss", func() {
					_, err := c.Cache.Get(context.Background(), "key1")
					Expect(err).To(Equal(certify.ErrCacheMiss))
				})
			})

			Context("when deleting a key that doesn't exist", func() {
				It("does not return an error", func() {
					Expect(c.Cache.Delete(context.Background(), "key1")).To(Succeed())
				})
			})

			Context("when accessing the cache concurrently", func() {
				It("does not cause any race conditions", func() {
					start := make(chan struct{})
					wg := sync.WaitGroup{}
					key := "key1"

					cert := &tls.Certificate{
						Leaf: &x509.Certificate{
							IsCA: true,
						},
					}

					for i := 0; i < 3; i++ {
						wg.Add(1)
						go func() {
							defer wg.Done()
							defer GinkgoRecover()

							Eventually(start).Should(BeClosed())
							Expect(c.Cache.Put(context.Background(), key, cert)).To(Succeed())
							Expect(c.Cache.Get(context.Background(), key)).NotTo(BeNil())
						}()
					}

					// Synchronize goroutines
					close(start)
					wg.Wait()

					Expect(c.Cache.Delete(context.Background(), key)).To(Succeed())
				})
			})
		})
	}
})

var _ = Describe("Certify", func() {
	It("issues a valid certificate", func() {
		serverName := "myotherserver.com"
		issuer := &mocks.IssuerMock{}
		cli := &certify.Certify{
			CommonName: "myserver.com",
			Issuer:     issuer,
			CertConfig: &certify.CertConfig{
				SubjectAlternativeNames:   []string{"extraname.com"},
				IPSubjectAlternativeNames: []net.IP{net.IPv4(1, 2, 3, 4)},
			},
		}
		issuer.IssueFunc = func(in1 context.Context, in2 string, in3 *certify.CertConfig) (*tls.Certificate, error) {
			defer GinkgoRecover()
			Expect(in2).To(Equal(cli.CommonName))
			switch len(issuer.IssueCalls()) {
			case 1:
				// First call is GetCertificate
				Expect(in3).To(Equal(&certify.CertConfig{
					SubjectAlternativeNames:   append(cli.CertConfig.SubjectAlternativeNames, serverName, cli.CommonName),
					IPSubjectAlternativeNames: cli.CertConfig.IPSubjectAlternativeNames,
				}))
			case 2:
				// Second call is GetClientCertificate
				Expect(in3).To(Equal(&certify.CertConfig{
					SubjectAlternativeNames:   append(cli.CertConfig.SubjectAlternativeNames, cli.CommonName),
					IPSubjectAlternativeNames: cli.CertConfig.IPSubjectAlternativeNames,
				}))
			}
			return &tls.Certificate{}, nil
		}

		_, err := cli.GetCertificate(&tls.ClientHelloInfo{
			ServerName: serverName,
		})
		Expect(err).To(Succeed())
		_, err = cli.GetClientCertificate(nil)
		Expect(err).To(Succeed())

		Expect(issuer.IssueCalls()).To(HaveLen(2))
	})

	Context("and there is a matching certificate in the cache", func() {
		It("doesn't request a new one from Vault", func() {
			issuer := &mocks.IssuerMock{}
			cli := &certify.Certify{
				CommonName: "myserver.com",
				Issuer:     issuer,
				Cache:      certify.NewMemCache(),
			}

			issuer.IssueFunc = func(in1 context.Context, in2 string, in3 *certify.CertConfig) (*tls.Certificate, error) {
				defer GinkgoRecover()
				Expect(in2).To(Equal(cli.CommonName))
				Expect(in3).To(Equal(&certify.CertConfig{
					SubjectAlternativeNames: []string{cli.CommonName},
				}))
				return &tls.Certificate{
					Leaf: &x509.Certificate{
						NotAfter: time.Now().Add(time.Minute),
					},
				}, nil
			}

			_, err := cli.GetCertificate(&tls.ClientHelloInfo{
				ServerName: cli.CommonName,
			})
			Expect(err).To(Succeed())

			_, err = cli.GetClientCertificate(nil)
			Expect(err).To(Succeed())

			// Should only have called once
			Expect(issuer.IssueCalls()).To(HaveLen(1))
		})

		Context("but the certificate expiry is within the RenewBefore", func() {
			It("requests a new certificate", func() {
				issuer := &mocks.IssuerMock{}
				cli := &certify.Certify{
					CommonName:  "myserver.com",
					Issuer:      issuer,
					Cache:       certify.NewMemCache(),
					RenewBefore: time.Hour,
				}
				issuer.IssueFunc = func(in1 context.Context, in2 string, in3 *certify.CertConfig) (*tls.Certificate, error) {
					defer GinkgoRecover()
					Expect(in2).To(Equal(cli.CommonName))
					Expect(in3).To(Equal(&certify.CertConfig{
						SubjectAlternativeNames: []string{cli.CommonName},
					}))
					return &tls.Certificate{
						Leaf: &x509.Certificate{
							NotAfter: time.Now().Add(time.Minute),
						},
					}, nil
				}

				_, err := cli.GetCertificate(&tls.ClientHelloInfo{
					ServerName: cli.CommonName,
				})
				Expect(err).To(Succeed())

				_, err = cli.GetClientCertificate(nil)
				Expect(err).To(Succeed())

				Expect(issuer.IssueCalls()).To(HaveLen(2))
			})
		})
	})

	Context("when the server name can be parsed as an IP", func() {
		It("populates the IPSubjectAlternativeNames", func() {
			serverName := "8.8.8.8"
			issuer := &mocks.IssuerMock{}
			cli := &certify.Certify{
				CommonName: "myserver.com",
				Issuer:     issuer,
			}
			issuer.IssueFunc = func(in1 context.Context, in2 string, in3 *certify.CertConfig) (*tls.Certificate, error) {
				defer GinkgoRecover()
				Expect(in2).To(Equal(cli.CommonName))
				Expect(in3).To(Equal(&certify.CertConfig{
					SubjectAlternativeNames:   []string{cli.CommonName},
					IPSubjectAlternativeNames: []net.IP{net.ParseIP(serverName)},
				}))
				return &tls.Certificate{}, nil
			}

			_, err := cli.GetCertificate(&tls.ClientHelloInfo{
				ServerName: serverName,
			})
			Expect(err).To(Succeed())
			Expect(issuer.IssueCalls()).To(HaveLen(1))
		})
	})

	Context("when several requests are made at the same time", func() {
		It("only calls to the issuer once", func() {
			issuer := &mocks.IssuerMock{}
			cli := &certify.Certify{
				CommonName: "myserver.com",
				Issuer:     issuer,
			}
			wait := make(chan struct{})
			issuer.IssueFunc = func(in1 context.Context, in2 string, in3 *certify.CertConfig) (*tls.Certificate, error) {
				defer GinkgoRecover()
				Expect(in2).To(Equal(cli.CommonName))
				Expect(in3).To(Equal(&certify.CertConfig{
					SubjectAlternativeNames: []string{cli.CommonName},
				}))
				<-wait
				return &tls.Certificate{
					Leaf: &x509.Certificate{
						SerialNumber: big.NewInt(100),
					},
				}, nil
			}

			gr1 := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				cert, err := cli.GetClientCertificate(nil)
				Expect(err).To(Succeed())
				Expect(cert.Leaf.SerialNumber.Int64()).To(BeEquivalentTo(100))
				close(gr1)
			}()

			gr2 := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				cert, err := cli.GetClientCertificate(nil)
				Expect(err).To(Succeed())
				Expect(cert.Leaf.SerialNumber.Int64()).To(BeEquivalentTo(100))
				close(gr2)
			}()

			time.Sleep(time.Millisecond)

			close(wait)
			Eventually(gr1).Should(BeClosed())
			Eventually(gr2).Should(BeClosed())

			Expect(issuer.IssueCalls()).To(HaveLen(1))
		})
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
						URL:   vaultConf.URL,
						Token: vaultConf.Token,
						Role:  vaultConf.Role,
						TLSConfig: &tls.Config{
							RootCAs: vaultConf.CertPool,
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
				cp.AddCert(vaultConf.CA)
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
				cp.AddCert(vaultConf.CA)
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
