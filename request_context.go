//go:build !go1.17
// +build !go1.17

package certify

import (
	"context"
	"crypto/tls"
)

func getRequestContext(hello *tls.ClientHelloInfo) context.Context {
	return context.Background()
}

func getClientRequestContext(cri *tls.CertificateRequestInfo) context.Context {
	return context.Background()
}
