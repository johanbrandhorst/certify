package certbot_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"net"
	"net/url"
	"path"
	"testing"
	"time"

	"github.com/fsouza/go-dockerclient"
	"github.com/hashicorp/vault/api"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/ory/dockertest"
)

func TestCertBot(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "CertBot Suite")
}

var (
	pool           *dockertest.Pool
	vaultContainer *dockertest.Resource
	vaultURL       *url.URL
	rootToken      string
	testRole       string
	wait           docker.CloseWaiter
	httpCertPEM    []byte
	caCert         *x509.Certificate
)

var _ = BeforeSuite(func() {
	rootToken = "mysecrettoken"
	testRole = "test"

	var key []byte
	var err error
	httpCertPEM, key, err = generateCertAndKey("localhost", net.IPv4(127, 0, 0, 1))
	Expect(err).To(Succeed())
	d, err := ioutil.TempDir("", "dockertest")
	Expect(err).To(Succeed())
	certFile := path.Join(d, "cert.pem")
	keyFile := path.Join(d, "key.pem")
	Expect(ioutil.WriteFile(certFile, httpCertPEM, 0644)).To(Succeed())
	Expect(ioutil.WriteFile(keyFile, key, 0644)).To(Succeed())

	By("Starting the Vault container", func() {
		var err error
		pool, err = dockertest.NewPool("")
		Expect(err).To(Succeed())

		vaultContainer, err = pool.RunWithOptions(&dockertest.RunOptions{
			Repository: "vault",
			Env: []string{
				"VAULT_DEV_ROOT_TOKEN_ID=" + rootToken,
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
			Mounts: []string{
				certFile + ":/vault/file/cert.pem",
				keyFile + ":/vault/file/key.pem",
			},
			ExposedPorts: []string{"8201"},
			PortBindings: map[docker.Port][]docker.PortBinding{
				"8201": []docker.PortBinding{{HostPort: "8201"}},
			},
		})
		Expect(err).To(Succeed())

		wait, err = pool.Client.AttachToContainerNonBlocking(docker.AttachToContainerOptions{
			Container:    vaultContainer.Container.ID,
			OutputStream: GinkgoWriter,
			ErrorStream:  GinkgoWriter,
			Stderr:       true,
			Stdout:       true,
			Stream:       true,
		})
		Expect(err).To(Succeed())

		vaultURL = &url.URL{
			Scheme: "https",
			Host:   net.JoinHostPort("localhost", "8201"),
		}
	})

	By("Mounting the PKI backend and creating the role", func() {
		conf := api.DefaultConfig()
		conf.Address = "http://" + net.JoinHostPort(vaultContainer.Container.NetworkSettings.IPAddress, "8200")
		cli, err := api.NewClient(conf)
		Expect(err).To(Succeed())
		cli.SetToken(rootToken)

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
			"ip_sans":     vaultContainer.Container.NetworkSettings.IPAddress,
			"format":      "der",
		})
		Expect(err).To(Succeed())
		caCertDER, err := base64.StdEncoding.DecodeString(resp.Data["certificate"].(string))
		Expect(err).To(Succeed())
		caCert, err = x509.ParseCertificate(caCertDER)
		Expect(err).To(Succeed())

		_, err = cli.Logical().Write("pki/roles/"+testRole, map[string]interface{}{
			"allowed_domains":  "myserver.com",
			"allow_subdomains": true,
			"allow_any_name":   true,
		})
		Expect(err).To(Succeed())
	})
})

var _ = AfterSuite(func() {
	if pool != nil {
		if vaultContainer != nil {
			Expect(wait.Close()).To(Succeed())
			Expect(wait.Wait()).To(Succeed())
			Expect(pool.Purge(vaultContainer)).To(Succeed())
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
			CommonName: "CertBot Test Cert",
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
