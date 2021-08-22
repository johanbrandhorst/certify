//go:build go1.17
// +build go1.17

package certify

import (
	"context"
	"crypto/tls"
)

func getRequestContext(hello *tls.ClientHelloInfo) context.Context {
	ctx := hello.Context()
	// This is only necessary because we can't set the context in our tests
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func getClientRequestContext(cri *tls.CertificateRequestInfo) context.Context {
	ctx := cri.Context()
	// This is only necessary because we can't set the context in our tests
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
