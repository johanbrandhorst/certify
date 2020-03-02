package csr_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestCSR(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "CSR Suite")
}
