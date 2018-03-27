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

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/grpclog"

	"github.com/johanbrandhorst/certify"
	"github.com/johanbrandhorst/certify/proto"
)

//go:generate protoc --go_out=plugins=grpc:./ ./proto/test.proto

func mustMakeTempDir() string {
	n, err := ioutil.TempDir("", "")
	if err != nil {
		panic(err)
	}
	return n
}

var _ = Describe("Certify", func() {
	var issuer certify.Issuer

	Context("when using a Vault Issuer", func() {
		BeforeEach(func() {
			cp := x509.NewCertPool()
			Expect(cp.AppendCertsFromPEM(httpCertPEM)).To(BeTrue())
			iss := &certify.VaultIssuer{
				VaultURL: vaultURL,
				Token:    rootToken,
				Role:     testRole,
				TLSConfig: &tls.Config{
					RootCAs: cp,
				},
			}
			Expect(iss.Connect(context.Background())).To(Succeed())
			issuer = iss
		})

		It("issues a valid certificate", func() {
			cli := &certify.Certify{
				CommonName: "myserver.com",
				Issuer:     issuer,
				CertConfig: &certify.CertConfig{
					TimeToLive:                time.Minute * 10,
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
			Expect(cert1.Leaf.NotAfter).To(BeTemporally("~", time.Now().Add(cli.CertConfig.TimeToLive), 2*time.Second))
			Expect(cert1.Leaf.Issuer.SerialNumber).To(Equal(caCert.Subject.SerialNumber))

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
			Expect(cert2.Leaf.NotAfter).To(BeTemporally("~", time.Now().Add(cli.CertConfig.TimeToLive), 2*time.Second))
			Expect(cert2.Leaf.Issuer.SerialNumber).To(Equal(caCert.Subject.SerialNumber))
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
				Expect(cert1.Leaf.Issuer.SerialNumber).To(Equal(caCert.Subject.SerialNumber))

				cert2, err := cli.GetClientCertificate(nil)
				Expect(err).To(Succeed())
				Expect(cert2).To(Equal(cert1)) // If these are equal, it can't have requested a new one
			})

			Context("but the certificate expiry is within the RenewThreshold", func() {
				It("requests a new certificate", func() {
					cli := &certify.Certify{
						CommonName:     "myserver.com",
						Issuer:         issuer,
						Cache:          certify.NewMemCache(),
						RenewThreshold: time.Hour,
						CertConfig: &certify.CertConfig{
							// Create certs with lower TTL than RenewThreshold
							// to force renewal every time.
							TimeToLive: 30 * time.Minute,
						},
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
					Expect(cert1.Leaf.NotAfter).To(BeTemporally("~", time.Now().Add(cli.CertConfig.TimeToLive), 2*time.Second))
					Expect(cert1.Leaf.Issuer.SerialNumber).To(Equal(caCert.Subject.SerialNumber))

					cert2, err := cli.GetClientCertificate(nil)
					Expect(err).To(Succeed())
					Expect(cert2).NotTo(BeNil())
					Expect(cert1).NotTo(Equal(cert2))
					Expect(cert2.Leaf).NotTo(BeNil())
					Expect(cert2.Leaf.Subject.CommonName).To(Equal(cli.CommonName))
					Expect(cert2.Leaf.DNSNames).To(Equal(append(cli.CertConfig.SubjectAlternativeNames, cli.CommonName)))
					Expect(cert2.Leaf.NotBefore).To(BeTemporally("<", time.Now()))
					Expect(cert2.Leaf.NotAfter).To(BeTemporally("~", time.Now().Add(cli.CertConfig.TimeToLive), 2*time.Second))
					Expect(cert2.Leaf.Issuer.SerialNumber).To(Equal(caCert.Subject.SerialNumber))
				})
			})
		})
	})
})

var _ = Describe("The Cache", func() {
	caches := []struct {
		Type  string
		Cache certify.Cache
	}{
		{Type: "MemCache", Cache: certify.NewMemCache()},
		{Type: "DirCache", Cache: certify.DirCache(mustMakeTempDir())},
	}

	for _, cache := range caches {
		c := cache
		Context("when using a "+c.Type, func() {
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
				cp := x509.NewCertPool()
				Expect(cp.AppendCertsFromPEM(httpCertPEM)).To(BeTrue())
				cb = &certify.Certify{
					CommonName: "Certify",
					Issuer: &certify.VaultIssuer{
						VaultURL: vaultURL,
						Token:    rootToken,
						Role:     testRole,
						TLSConfig: &tls.Config{
							RootCAs: cp,
						},
					},
					Cache:          certify.NewMemCache(),
					RenewThreshold: time.Hour,
				}
			})

			By("Starting the gRPC Server", func() {
				var err error

				grpclog.SetLoggerV2(grpclog.NewLoggerV2(GinkgoWriter, ioutil.Discard, ioutil.Discard))
				lis, err = net.Listen("tcp", addr)
				Expect(err).To(Succeed())

				cp := x509.NewCertPool()
				cp.AddCert(caCert)
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
				cp.AddCert(caCert)
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
