# Certbot
[![GoDoc](https://godoc.org/github.com/johanbrandhorst/certbot?status.svg)](https://godoc.org/github.com/johanbrandhorst/certbot)
[![Go Report Card](https://goreportcard.com/badge/github.com/johanbrandhorst/certbot)](https://goreportcard.com/report/github.com/johanbrandhorst/certbot)

Certbot allows easy automatic certificate distribution and maintenance.
Certificates are requested as TLS connectoins
are made, courtesy of the `GetCertificate` and `GetClientCertificate`
`tls.Config` hooks. Certificates are optionally cached.

## Issuers

Certbot exposes an `Issuer` interface which is used to allow switching
between issuer backends.

Currently implemented issuers:

- Vault PKI Secrets Engine

## Usage

Create an issuer:
```go
issuer := &certbot.VaultIssuer{
    VaultURL: &url.URL{
        Scheme: "https",
        Host: "my-local-vault-instance.com"
    },
    Token:     "myVaultToken",
    Role:      "myVaultRole",
}
```

Create a Certbot:
```go
c := &certbot.Certbot{
    CommonName: "MyServer.com",
    Issuer: issuer,
    // It is recommended to use a cache.
    Cache: certbot.NewMemCache(),
    // It is recommended to set a RenewThreshold.
    // Refresh cached certificates when < 24H left before expiry.
    RenewThreshold: 24*time.Hour,
}
```

Use in your TLS Config:
```go
tlsConfig := &tls.Config{
    GetCertificate: certBot.GetCertificate,
}
```

That's it! Both server-side and client-side certificates
can be generated:

```go
tlsConfig := &tls.Config{
    GetClientCertificate: certBot.GetClientCertificate,
}
```

For an end-to-end example using gRPC with mutual TLS authentication,
see the tests.
