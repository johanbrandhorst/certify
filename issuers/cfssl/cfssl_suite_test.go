package cfssl_test

import (
	"archive/tar"
	"bytes"
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
	"os"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/api/client"
	"github.com/cloudflare/cfssl/config"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
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
	pool      *dockertest.Pool
	resources []*dockertest.Resource
	waiters   []docker.CloseWaiter

	cfsslConf, cfsslTLSConf cfsslConfig
)

var _ = BeforeSuite(func() {
	host := "localhost"
	if os.Getenv("DOCKER_HOST") != "" {
		u, err := url.Parse(os.Getenv("DOCKER_HOST"))
		Expect(err).To(Succeed())
		host, _, err = net.SplitHostPort(u.Host)
		Expect(err).To(Succeed())
	}

	log.SetOutput(GinkgoWriter)

	cert, key, err := generateCertAndKey(host, net.IPv4(0, 0, 0, 0), net.IPv6zero)
	Expect(err).To(Succeed())

	pool, err = dockertest.NewPool("")
	Expect(err).To(Succeed())

	pool.MaxWait = time.Second * 10

	By("Starting the CFSSL container", func() {
		cp := x509.NewCertPool()
		Expect(cp.AppendCertsFromPEM(cert)).To(BeTrue())
		cfsslConf = cfsslConfig{
			Profile:  "authed",
			CertPool: cp,
		}
		repo := "cfssl/cfssl"
		version := "1.6.0"
		img := repo + ":" + version
		_, err = pool.Client.InspectImage(img)
		if err != nil {
			// Pull image
			Expect(pool.Client.PullImage(docker.PullImageOptions{
				Repository:   repo,
				Tag:          version,
				OutputStream: GinkgoWriter,
			}, docker.AuthConfiguration{})).To(Succeed())
		}

		c, err := pool.Client.CreateContainer(docker.CreateContainerOptions{
			Name: "cfssl",
			Config: &docker.Config{
				Image: img,
				ExposedPorts: map[docker.Port]struct{}{
					docker.Port("8888"): {},
				},
				Cmd: []string{
					"serve",
					"-loglevel", "0",
					"-address", "0.0.0.0",
					"-port", "8888",
					"-ca", "/cert.pem",
					"-ca-key", "/key.pem",
					"-config", "/conf.json",
				},
			},
			HostConfig: &docker.HostConfig{
				PublishAllPorts: true,
				PortBindings: map[docker.Port][]docker.PortBinding{
					"8888": {{HostPort: "8888"}},
				},
			},
		})
		Expect(err).To(Succeed())

		b := &bytes.Buffer{}
		archive := tar.NewWriter(b)
		Expect(archive.WriteHeader(&tar.Header{
			Name: "/cert.pem",
			Mode: 0o644,
			Size: int64(len(cert)),
		})).To(Succeed())
		Expect(archive.Write(cert)).To(Equal(len(cert)))
		Expect(archive.WriteHeader(&tar.Header{
			Name: "/key.pem",
			Mode: 0o644,
			Size: int64(len(key)),
		})).To(Succeed())
		Expect(archive.Write(key)).To(Equal(len(key)))
		const authKey = "testKey"
		conf := config.Config{
			Signing: &config.Signing{
				Profiles: map[string]*config.SigningProfile{
					cfsslConf.Profile: {
						AuthKeyName:  authKey,
						Usage:        []string{"signing", "key encipherment", "server auth", "client auth"},
						Expiry:       time.Hour * 8760,
						ExpiryString: "8760h",
					},
				},
				Default: config.DefaultConfig(),
			},
			AuthKeys: map[string]config.AuthKey{
				authKey: {
					Type: "standard",
					Key:  "0123456789ABCDEF0123456789ABCDEF",
				},
			},
		}
		confBytes, err := json.Marshal(&conf)
		Expect(err).To(Succeed())
		Expect(archive.WriteHeader(&tar.Header{
			Name: "/conf.json",
			Mode: 0o644,
			Size: int64(len(confBytes)),
		})).To(Succeed())
		Expect(archive.Write(confBytes)).To(Equal(len(confBytes)))
		Expect(archive.Close()).To(Succeed())

		Expect(pool.Client.UploadToContainer(c.ID, docker.UploadToContainerOptions{
			InputStream: b,
			Path:        "/",
		})).To(Succeed())

		Expect(pool.Client.StartContainer(c.ID, nil)).To(Succeed())

		c, err = pool.Client.InspectContainer(c.ID)
		Expect(err).To(Succeed())

		waiter, err := pool.Client.AttachToContainerNonBlocking(docker.AttachToContainerOptions{
			Container:    c.ID,
			OutputStream: GinkgoWriter,
			ErrorStream:  GinkgoWriter,
			Stderr:       true,
			Stdout:       true,
			Stream:       true,
		})
		Expect(err).To(Succeed())
		waiters = append(waiters, waiter)

		resources = append(resources, &dockertest.Resource{Container: c})

		cfsslConf.URL = &url.URL{
			Scheme: "http",
			Host:   net.JoinHostPort(host, "8888"),
		}
		cfsslConf.AuthKey = conf.AuthKeys[authKey].Key

		remote := client.NewServerTLS(cfsslConf.URL.String(), &tls.Config{RootCAs: cp})
		Expect(pool.Retry(func() error {
			_, err = remote.Info([]byte(`{}`))
			return err
		})).To(Succeed())
	})

	By("Starting the CFSSL TLS container", func() {
		cp := x509.NewCertPool()
		Expect(cp.AppendCertsFromPEM(cert)).To(BeTrue())
		cfsslTLSConf = cfsslConfig{
			Profile:  "authed",
			CertPool: cp,
		}
		repo := "cfssl/cfssl"
		version := "1.6.0"
		img := repo + ":" + version
		_, err = pool.Client.InspectImage(img)
		if err != nil {
			// Pull image
			Expect(pool.Client.PullImage(docker.PullImageOptions{
				Repository:   repo,
				Tag:          version,
				OutputStream: GinkgoWriter,
			}, docker.AuthConfiguration{})).To(Succeed())
		}

		c, err := pool.Client.CreateContainer(docker.CreateContainerOptions{
			Name: "cfssl-tls",
			Config: &docker.Config{
				Image: img,
				ExposedPorts: map[docker.Port]struct{}{
					docker.Port("8889"): {},
				},
				Cmd: []string{
					"serve",
					"-loglevel", "0",
					"-address", "0.0.0.0",
					"-port", "8889",
					"-ca", "/cert.pem",
					"-ca-key", "/key.pem",
					"-tls-cert", "/cert.pem",
					"-tls-key", "/key.pem",
					"-config", "/conf.json",
				},
			},
			HostConfig: &docker.HostConfig{
				PublishAllPorts: true,
				PortBindings: map[docker.Port][]docker.PortBinding{
					"8889": {{HostPort: "8889"}},
				},
			},
		})
		Expect(err).To(Succeed())

		b := &bytes.Buffer{}
		archive := tar.NewWriter(b)
		Expect(archive.WriteHeader(&tar.Header{
			Name: "/cert.pem",
			Mode: 0o644,
			Size: int64(len(cert)),
		})).To(Succeed())
		Expect(archive.Write(cert)).To(Equal(len(cert)))
		Expect(archive.WriteHeader(&tar.Header{
			Name: "/key.pem",
			Mode: 0o644,
			Size: int64(len(key)),
		})).To(Succeed())
		Expect(archive.Write(key)).To(Equal(len(key)))
		const authKey = "testKey"
		conf := config.Config{
			Signing: &config.Signing{
				Profiles: map[string]*config.SigningProfile{
					cfsslTLSConf.Profile: {
						AuthKeyName:  authKey,
						Usage:        []string{"signing", "key encipherment", "server auth", "client auth"},
						Expiry:       time.Hour * 8760,
						ExpiryString: "8760h",
					},
				},
				Default: config.DefaultConfig(),
			},
			AuthKeys: map[string]config.AuthKey{
				authKey: {
					Type: "standard",
					Key:  "0123456789ABCDEF0123456789ABCDEF",
				},
			},
		}
		confBytes, err := json.Marshal(&conf)
		Expect(err).To(Succeed())
		Expect(archive.WriteHeader(&tar.Header{
			Name: "/conf.json",
			Mode: 0o644,
			Size: int64(len(confBytes)),
		})).To(Succeed())
		Expect(archive.Write(confBytes)).To(Equal(len(confBytes)))
		Expect(archive.Close()).To(Succeed())

		Expect(pool.Client.UploadToContainer(c.ID, docker.UploadToContainerOptions{
			InputStream: b,
			Path:        "/",
		})).To(Succeed())

		Expect(pool.Client.StartContainer(c.ID, nil)).To(Succeed())

		c, err = pool.Client.InspectContainer(c.ID)
		Expect(err).To(Succeed())

		waiter, err := pool.Client.AttachToContainerNonBlocking(docker.AttachToContainerOptions{
			Container:    c.ID,
			OutputStream: GinkgoWriter,
			ErrorStream:  GinkgoWriter,
			Stderr:       true,
			Stdout:       true,
			Stream:       true,
		})
		waiters = append(waiters, waiter)

		resources = append(resources, &dockertest.Resource{Container: c})

		cfsslTLSConf.URL = &url.URL{
			Scheme: "https",
			Host:   net.JoinHostPort(host, "8889"),
		}
		cfsslTLSConf.AuthKey = conf.AuthKeys[authKey].Key

		remote := client.NewServerTLS(cfsslTLSConf.URL.String(), &tls.Config{RootCAs: cp})
		Expect(pool.Retry(func() error {
			_, err = remote.Info([]byte(`{}`))
			return err
		})).To(Succeed())
	})
})

var _ = AfterSuite(func() {
	for _, waiter := range waiters {
		Expect(waiter.Close()).To(Succeed())
		Expect(waiter.Wait()).To(Succeed())
	}
	for _, resource := range resources {
		Expect(pool.Purge(resource)).To(Succeed())
	}
})

func generateCertAndKey(SAN string, IPSAN ...net.IP) ([]byte, []byte, error) {
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
		IPAddresses:           IPSAN,
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
