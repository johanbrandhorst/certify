package certify_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
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
	"github.com/johanbrandhorst/certify/proto"
)

//go:generate protoc --go_out=plugins=grpc:./ ./proto/test.proto

var _ = Describe("Issuers", func() {
	issuers := []struct {
		Type     string
		IssuerFn func() certify.Issuer
	}{
		{Type: "Vault", IssuerFn: func() certify.Issuer {
			return &certify.VaultIssuer{
				VaultURL: vaultConf.URL,
				Token:    vaultConf.Token,
				Role:     vaultConf.Role,
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
			return &certify.CFSSLIssuer{
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
			return &certify.CFSSLIssuer{
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

				if vIss, ok := iss.(*certify.VaultIssuer); ok {
					Expect(tlsCert.Leaf.NotBefore).To(BeTemporally("<", time.Now()))
					Expect(tlsCert.Leaf.NotAfter).To(BeTemporally("~", time.Now().Add(vIss.TimeToLive), 5*time.Second))
				}
			})

			Context("when specifying some SANs, IPSANs and OtherSANs", func() {
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

					if vIss, ok := iss.(*certify.VaultIssuer); ok {
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
	Context("when using a Vault Issuer", func() {
		var issuer *certify.VaultIssuer
		BeforeEach(func() {
			issuer = &certify.VaultIssuer{
				VaultURL: vaultConf.URL,
				Token:    vaultConf.Token,
				Role:     vaultConf.Role,
				TLSConfig: &tls.Config{
					RootCAs: vaultConf.CertPool,
				},
				TimeToLive: time.Minute * 10,
			}
		})

		It("issues a valid certificate", func() {
			cli := &certify.Certify{
				CommonName: "myserver.com",
				Issuer:     issuer,
				CertConfig: &certify.CertConfig{
					SubjectAlternativeNames:   []string{"extraname.com"},
					IPSubjectAlternativeNames: []net.IP{net.IPv4(1, 2, 3, 4)},
				},
			}

			cert1, err := cli.GetCertificate(&tls.ClientHelloInfo{
				ServerName: "myotherserver.com",
			})
			Expect(err).To(Succeed())
			Expect(cert1).NotTo(BeNil())
			Expect(cert1.Leaf).NotTo(BeNil())
			Expect(cert1.Leaf.Subject.CommonName).To(Equal(cli.CommonName))
			Expect(cert1.Leaf.DNSNames).To(Equal([]string{cli.CertConfig.SubjectAlternativeNames[0], "myotherserver.com"}))
			Expect(cert1.Leaf.IPAddresses).To(HaveLen(1))
			Expect(cert1.Leaf.IPAddresses[0].Equal(cli.CertConfig.IPSubjectAlternativeNames[0])).To(BeTrue())
			Expect(cert1.Leaf.NotBefore).To(BeTemporally("<", time.Now()))
			Expect(cert1.Leaf.NotAfter).To(BeTemporally("~", time.Now().Add(issuer.TimeToLive), 5*time.Second))
			Expect(cert1.Leaf.Issuer.SerialNumber).To(Equal(vaultConf.CA.Subject.SerialNumber))

			cert2, err := cli.GetClientCertificate(nil)
			Expect(err).To(Succeed())
			Expect(cert2).NotTo(BeNil())
			Expect(cert1).NotTo(Equal(cert2))
			Expect(cert2.Leaf).NotTo(BeNil())
			Expect(cert2.Leaf.Subject.CommonName).To(Equal(cli.CommonName))
			Expect(cert2.Leaf.DNSNames).To(Equal(append(cli.CertConfig.SubjectAlternativeNames, cli.CommonName)))
			Expect(cert2.Leaf.IPAddresses).To(HaveLen(1))
			Expect(cert2.Leaf.IPAddresses[0].Equal(cli.CertConfig.IPSubjectAlternativeNames[0])).To(BeTrue())
			Expect(cert2.Leaf.NotBefore).To(BeTemporally("<", time.Now()))
			Expect(cert2.Leaf.NotAfter).To(BeTemporally("~", time.Now().Add(issuer.TimeToLive), 5*time.Second))
			Expect(cert2.Leaf.Issuer.SerialNumber).To(Equal(vaultConf.CA.Subject.SerialNumber))
		})

		Context("when there is a matching certificate in the cache", func() {
			It("doesn't request a new one from Vault", func() {
				cli := &certify.Certify{
					CommonName: "myserver.com",
					Issuer:     issuer,
					Cache:      certify.NewMemCache(),
				}

				cert1, err := cli.GetCertificate(&tls.ClientHelloInfo{
					ServerName: cli.CommonName,
				})
				Expect(err).To(Succeed())
				Expect(cert1).NotTo(BeNil())
				Expect(cert1.Leaf).NotTo(BeNil())
				Expect(cert1.Leaf.Subject.CommonName).To(Equal(cli.CommonName))
				Expect(cert1.Leaf.DNSNames).To(ConsistOf(cli.CommonName))
				Expect(cert1.Leaf.NotBefore).To(BeTemporally("<", time.Now()))
				Expect(cert1.Leaf.NotAfter).To(BeTemporally(">", time.Now()))
				Expect(cert1.Leaf.Issuer.SerialNumber).To(Equal(vaultConf.CA.Subject.SerialNumber))

				cert2, err := cli.GetClientCertificate(nil)
				Expect(err).To(Succeed())
				Expect(cert2).To(Equal(cert1)) // If these are equal, it can't have requested a new one
			})

			Context("but the certificate expiry is within the RenewBefore", func() {
				It("requests a new certificate", func() {
					// Create certs with lower TTL than RenewBefore
					// to force renewal every time.
					issuer.TimeToLive = 30 * time.Minute
					cli := &certify.Certify{
						CommonName:  "myserver.com",
						Issuer:      issuer,
						Cache:       certify.NewMemCache(),
						RenewBefore: time.Hour,
					}

					cert1, err := cli.GetCertificate(&tls.ClientHelloInfo{
						ServerName: cli.CommonName,
					})
					Expect(err).To(Succeed())
					Expect(cert1).NotTo(BeNil())
					Expect(cert1.Leaf).NotTo(BeNil())
					Expect(cert1.Leaf.Subject.CommonName).To(Equal(cli.CommonName))
					Expect(cert1.Leaf.DNSNames).To(ConsistOf(cli.CommonName))
					Expect(cert1.Leaf.NotBefore).To(BeTemporally("<", time.Now()))
					Expect(cert1.Leaf.NotAfter).To(BeTemporally("~", time.Now().Add(issuer.TimeToLive), 5*time.Second))
					Expect(cert1.Leaf.Issuer.SerialNumber).To(Equal(vaultConf.CA.Subject.SerialNumber))

					cert2, err := cli.GetClientCertificate(nil)
					Expect(err).To(Succeed())
					Expect(cert2).NotTo(BeNil())
					Expect(cert1).NotTo(Equal(cert2))
					Expect(cert2.Leaf).NotTo(BeNil())
					Expect(cert2.Leaf.Subject.CommonName).To(Equal(cli.CommonName))
					Expect(cert2.Leaf.NotBefore).To(BeTemporally("<", time.Now()))
					Expect(cert2.Leaf.NotAfter).To(BeTemporally("~", time.Now().Add(issuer.TimeToLive), 5*time.Second))
					Expect(cert2.Leaf.Issuer.SerialNumber).To(Equal(vaultConf.CA.Subject.SerialNumber))
				})
			})
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
					Issuer: &certify.VaultIssuer{
						VaultURL: vaultConf.URL,
						Token:    vaultConf.Token,
						Role:     vaultConf.Role,
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
