package cfssl_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/api/client"
	"github.com/cloudflare/cfssl/config"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/uw-labs/podrick"
	_ "github.com/uw-labs/podrick/runtimes/docker"
	_ "github.com/uw-labs/podrick/runtimes/podman"
)

func TestCFSSL(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "CFSSL Suite")
}

type cfsslConfig struct {
	URL      *url.URL
	CertPool *x509.CertPool
	AuthKey  string
	Profile  string
}

var (
	containers []podrick.Container

	cfsslConf, cfsslTLSConf cfsslConfig
)

var _ = BeforeSuite(func() {
	log.SetOutput(GinkgoWriter)

	cert, key, err := generateCertAndKey("localhost", net.IPv4(0, 0, 0, 0))
	Expect(err).To(Succeed())

	ctx := context.Background()

	By("Starting the CFSSL container", func() {
		cp := x509.NewCertPool()
		Expect(cp.AppendCertsFromPEM(cert)).To(BeTrue())
		cfsslConf = cfsslConfig{
			Profile:  "authed",
			CertPool: cp,
		}

		cmd := []string{
			"serve",
			"-loglevel", "0",
			"-address", "0.0.0.0",
			"-port", "8888",
			"-ca", "/cert.pem",
			"-ca-key", "/key.pem",
			"-config", "/conf.json",
		}

		const authKey = "testKey"
		conf := config.Config{
			Signing: &config.Signing{
				Profiles: map[string]*config.SigningProfile{
					cfsslConf.Profile: &config.SigningProfile{
						AuthKeyName:  authKey,
						Usage:        []string{"signing", "key encipherment", "server auth", "client auth"},
						Expiry:       time.Hour * 8760,
						ExpiryString: "8760h",
					},
				},
				Default: config.DefaultConfig(),
			},
			AuthKeys: map[string]config.AuthKey{
				authKey: config.AuthKey{
					Type: "standard",
					Key:  "0123456789ABCDEF0123456789ABCDEF",
				},
			},
		}
		confBytes, err := json.Marshal(&conf)
		Expect(err).NotTo(HaveOccurred())

		lc := func(address string) error {
			u := &url.URL{
				Scheme: "http",
				Host:   address,
			}
			remote := client.NewServerTLS(u.String(), &tls.Config{RootCAs: cp})
			_, err = remote.Info([]byte(`{}`))
			return err
		}

		ctr, err := podrick.StartContainer(ctx, "cfssl/cfssl", "1.3.2", "8888",
			podrick.WithCmd(cmd),
			podrick.WithFileUpload(podrick.File{
				Path:    "/cert.pem",
				Size:    len(cert),
				Content: bytes.NewReader(cert),
			}),
			podrick.WithFileUpload(podrick.File{
				Path:    "/key.pem",
				Size:    len(key),
				Content: bytes.NewReader(key),
			}),
			podrick.WithFileUpload(podrick.File{
				Path:    "/conf.json",
				Size:    len(confBytes),
				Content: bytes.NewReader(confBytes),
			}),
			podrick.WithLivenessCheck(lc),
		)
		Expect(err).To(Succeed())

		containers = append(containers, ctr)

		cfsslConf.URL = &url.URL{
			Scheme: "http",
			Host:   ctr.Address(),
		}
		cfsslConf.AuthKey = conf.AuthKeys[authKey].Key
	})

	By("Starting the CFSSL TLS container", func() {
		cp := x509.NewCertPool()
		Expect(cp.AppendCertsFromPEM(cert)).To(BeTrue())
		cfsslTLSConf = cfsslConfig{
			Profile:  "authed",
			CertPool: cp,
		}

		cmd := []string{
			"serve",
			"-loglevel", "0",
			"-address", "0.0.0.0",
			"-port", "8889",
			"-ca", "/cert.pem",
			"-ca-key", "/key.pem",
			"-tls-cert", "/cert.pem",
			"-tls-key", "/key.pem",
			"-config", "/conf.json",
		}

		const authKey = "testKey"
		conf := config.Config{
			Signing: &config.Signing{
				Profiles: map[string]*config.SigningProfile{
					cfsslTLSConf.Profile: &config.SigningProfile{
						AuthKeyName:  authKey,
						Usage:        []string{"signing", "key encipherment", "server auth", "client auth"},
						Expiry:       time.Hour * 8760,
						ExpiryString: "8760h",
					},
				},
				Default: config.DefaultConfig(),
			},
			AuthKeys: map[string]config.AuthKey{
				authKey: config.AuthKey{
					Type: "standard",
					Key:  "0123456789ABCDEF0123456789ABCDEF",
				},
			},
		}
		confBytes, err := json.Marshal(&conf)
		Expect(err).To(Succeed())

		lc := func(address string) error {
			u := &url.URL{
				Scheme: "https",
				Host:   address,
			}
			remote := client.NewServerTLS(u.String(), &tls.Config{
				RootCAs:            cp,
				InsecureSkipVerify: true,
			})
			_, err = remote.Info([]byte(`{}`))
			return err
		}

		ctr, err := podrick.StartContainer(ctx, "cfssl/cfssl", "1.3.2", "8889",
			podrick.WithCmd(cmd),
			podrick.WithFileUpload(podrick.File{
				Path:    "/cert.pem",
				Size:    len(cert),
				Content: bytes.NewReader(cert),
			}),
			podrick.WithFileUpload(podrick.File{
				Path:    "/key.pem",
				Size:    len(key),
				Content: bytes.NewReader(key),
			}),
			podrick.WithFileUpload(podrick.File{
				Path:    "/conf.json",
				Size:    len(confBytes),
				Content: bytes.NewReader(confBytes),
			}),
			podrick.WithLivenessCheck(lc),
		)
		Expect(err).To(Succeed())

		containers = append(containers, ctr)

		cfsslTLSConf.URL = &url.URL{
			Scheme: "https",
			Host:   ctr.Address(),
		}

		// Host is required when using TLS
		h, p, err := net.SplitHostPort(cfsslTLSConf.URL.Host)
		Expect(err).NotTo(HaveOccurred())
		if h == "" {
			cfsslTLSConf.URL.Host = net.JoinHostPort("localhost", p)
		}

		cfsslTLSConf.AuthKey = conf.AuthKeys[authKey].Key
	})
})

var _ = AfterSuite(func() {
	for _, c := range containers {
		Expect(c.Close(context.Background())).To(Succeed())
	}
})

func generateCertAndKey(SAN string, IPSAN net.IP) ([]byte, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "Certify Test Cert",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{SAN},
		IPAddresses:           []net.IP{IPSAN},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
	if err != nil {
		return nil, nil, err
	}
	certOut := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})
	keyOut := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})

	return certOut, keyOut, nil
}
