package cforigin_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloudflare/cloudflare-go"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestCloudflareOrigin(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Cloudflare origin Suite")
}

var (
	srv     *httptest.Server
	cli     *http.Client
	handler func(cloudflare.OriginCACertificate) (cloudflare.OriginCACertificate, error)
)

type originResp struct {
	cloudflare.Response
	Result cloudflare.OriginCACertificate
}

var _ = BeforeSuite(func() {
	handler = func(_ cloudflare.OriginCACertificate) (cloudflare.OriginCACertificate, error) {
		return cloudflare.OriginCACertificate{}, nil
	}
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer GinkgoRecover()

		Expect(r.Header.Get("Content-Type")).To(Equal("application/json"))

		switch r.URL.Path {
		case "/zones":
			Expect(r.Method).To(Equal("GET"))
			resp := cloudflare.ZonesResponse{
				Result: []cloudflare.Zone{
					{
						Name: "Zone1",
					},
					{
						Name: "Zone2",
					},
				},
			}
			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		case "/certificates":
			Expect(r.Method).To(Equal("POST"))
			var req cloudflare.OriginCACertificate
			err := json.NewDecoder(r.Body).Decode(&req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			resp, err := handler(req)
			or := originResp{
				Result: resp,
			}
			if err != nil {
				or.Success = false
				or.Errors = []cloudflare.ResponseInfo{
					{
						Message: err.Error(),
					},
				}
			} else {
				or.Success = true
			}
			err = json.NewEncoder(w).Encode(or)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		default:
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
	}))

	cp := x509.NewCertPool()
	cp.AddCert(srv.Certificate())
	cli = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: cp,
			},
		},
	}
})

var _ = AfterSuite(func() {
	srv.Close()
})
