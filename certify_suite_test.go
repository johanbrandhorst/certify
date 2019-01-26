package certify_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestCertify(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Certify Suite")
}
