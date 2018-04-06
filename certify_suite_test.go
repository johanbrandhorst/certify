package certify_test

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/fsouza/go-dockerclient"
	"github.com/hashicorp/vault/api"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/ory/dockertest"
)

func TestCertify(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Certify Suite")
}

type vaultConfig struct {
	Role        string
	Token       string
	URL         *url.URL
	CA          *x509.Certificate
	HTTPCertPEM []byte
}

var (
	pool      *dockertest.Pool
	resources []*dockertest.Resource
	waiters   []docker.CloseWaiter

	vaultConf vaultConfig
)

var _ = BeforeSuite(func() {
	host := "localhost"
	if os.Getenv("DOCKER_HOST") != "" {
		u, err := url.Parse(os.Getenv("DOCKER_HOST"))
		Expect(err).To(Succeed())
		host, _, err = net.SplitHostPort(u.Host)
		Expect(err).To(Succeed())
	}

	cert, key, err := generateCertAndKey(host, net.IPv4(127, 0, 0, 1))
	Expect(err).To(Succeed())

	b := &bytes.Buffer{}
	archive := tar.NewWriter(b)
	Expect(archive.WriteHeader(&tar.Header{
		Name: "/cert.pem",
		Mode: 0644,
		Size: int64(len(cert)),
	})).To(Succeed())
	Expect(archive.Write(cert)).To(Equal(len(cert)))
	Expect(archive.WriteHeader(&tar.Header{
		Name: "/key.pem",
		Mode: 0644,
		Size: int64(len(key)),
	})).To(Succeed())
	Expect(archive.Write(key)).To(Equal(len(key)))
	Expect(archive.Close()).To(Succeed())

	pool, err = dockertest.NewPool("")
	Expect(err).To(Succeed())

	By("Starting the Vault container", func() {
		vaultConf = vaultConfig{
			Token:       "mysecrettoken",
			Role:        "test",
			HTTPCertPEM: cert,
		}

		_, err = pool.Client.InspectImage("vault:latest")
		if err != nil {
			// Pull image
			Expect(pool.Client.PullImage(docker.PullImageOptions{
				Repository: "vault",
				Tag:        "latest",
			}, docker.AuthConfiguration{})).To(Succeed())
		}

		c, err := pool.Client.CreateContainer(docker.CreateContainerOptions{
			Name: "vault",
			Config: &docker.Config{
				Image: "vault:latest",
				Env: []string{
					"VAULT_DEV_ROOT_TOKEN_ID=" + vaultConf.Token,
					`VAULT_LOCAL_CONFIG={
						"default_lease_ttl": "168h",
						"max_lease_ttl": "720h",
						"disable_mlock": true,
						"listener": [{
							"tcp" :{
								"address": "0.0.0.0:8201",
								"tls_cert_file": "/vault/file/cert.pem",
								"tls_key_file": "/vault/file/key.pem"
							}
						}]
					}`,
				},
				ExposedPorts: map[docker.Port]struct{}{
					docker.Port("8200"): struct{}{},
					docker.Port("8201"): struct{}{},
				},
			},
			HostConfig: &docker.HostConfig{
				NetworkMode:     "host",
				PublishAllPorts: true,
				PortBindings: map[docker.Port][]docker.PortBinding{
					"8200": []docker.PortBinding{{HostPort: "8200"}},
					"8201": []docker.PortBinding{{HostPort: "8201"}},
				},
			},
		})
		Expect(err).To(Succeed())

		Expect(pool.Client.UploadToContainer(c.ID, docker.UploadToContainerOptions{
			InputStream: b,
			Path:        "/vault/file/",
		})).To(Succeed())

		Expect(pool.Client.StartContainer(c.ID, nil)).To(Succeed())

		c, err = pool.Client.InspectContainer(c.ID)
		Expect(err).To(Succeed())

		wait, err := pool.Client.AttachToContainerNonBlocking(docker.AttachToContainerOptions{
			Container:    c.ID,
			OutputStream: GinkgoWriter,
			ErrorStream:  GinkgoWriter,
			Stderr:       true,
			Stdout:       true,
			Stream:       true,
		})
		Expect(err).To(Succeed())

		waiters = append(waiters, wait)

		resources = append(resources, &dockertest.Resource{Container: c})

		vaultConf.URL = &url.URL{
			Scheme: "https",
			Host:   net.JoinHostPort(host, "8201"),
		}

		conf := api.DefaultConfig()
		conf.Address = "http://" + net.JoinHostPort(host, "8200")
		cli, err := api.NewClient(conf)
		Expect(err).To(Succeed())
		cli.SetToken(vaultConf.Token)

		Expect(pool.Retry(func() error {
			_, err := cli.Logical().Read("pki/certs")
			return err
		})).To(Succeed())

		Expect(cli.Sys().Mount("pki", &api.MountInput{
			Type: "pki",
			Config: api.MountConfigInput{
				MaxLeaseTTL: "87600h",
			},
		})).To(Succeed())
		resp, err := cli.Logical().Write("pki/root/generate/internal", map[string]interface{}{
			"ttl":         "87600h",
			"common_name": "my_vault",
			"ip_sans":     c.NetworkSettings.IPAddress,
			"format":      "der",
		})
		Expect(err).To(Succeed())
		caCertDER, err := base64.StdEncoding.DecodeString(resp.Data["certificate"].(string))
		Expect(err).To(Succeed())
		vaultConf.CA, err = x509.ParseCertificate(caCertDER)
		Expect(err).To(Succeed())

		_, err = cli.Logical().Write("pki/roles/"+vaultConf.Role, map[string]interface{}{
			"allowed_domains":  "myserver.com",
			"allow_subdomains": true,
			"allow_any_name":   true,
		})
		Expect(err).To(Succeed())
	})
})

var _ = AfterSuite(func() {
	for _, waiter := range waiters {
		Expect(waiter.Close()).To(Succeed())
		Expect(waiter.Wait()).To(Succeed())
	}
	if pool != nil {
		for _, resource := range resources {
			Expect(pool.Purge(resource)).To(Succeed())
		}
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
	certOut := new(bytes.Buffer)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyOut := new(bytes.Buffer)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return certOut.Bytes(), keyOut.Bytes(), nil
}
