package certify_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"math/big"
	"net"
	"sync"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/johanbrandhorst/certify"
	"github.com/johanbrandhorst/certify/mocks"
)

//go:generate moq -out mocks/issuer.mock.go -pkg mocks . Issuer

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

			// Let the goroutines start
			time.Sleep(10 * time.Millisecond)

			close(wait)
			Eventually(gr1).Should(BeClosed())
			Eventually(gr2).Should(BeClosed())

			Expect(issuer.IssueCalls()).To(HaveLen(1))
		})
	})
})
