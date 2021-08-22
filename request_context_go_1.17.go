//go:build go1.17
// +build go1.17

package certify

import (
	"context"
	"crypto/tls"
)

func getRequestContext(hello *tls.ClientHelloInfo) context.Context {
	return hello.Context()
}

func getClientRequestContext(cri *tls.CertificateRequestInfo) context.Context {
	return cri.Context()
}
