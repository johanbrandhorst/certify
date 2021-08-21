package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	"github.com/cloudflare/cfssl/auth"
	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"
	logrusadapter "logur.dev/adapter/logrus"

	"github.com/johanbrandhorst/certify"
	"github.com/johanbrandhorst/certify/cmd/proxy/internal/envtypes"
	"github.com/johanbrandhorst/certify/issuers/aws"
	"github.com/johanbrandhorst/certify/issuers/cfssl"
	"github.com/johanbrandhorst/certify/issuers/vault"
)

type configuration struct {
	Addr      string             `default:":443" desc:"The address to serve the proxy on."`
	ProxyAddr string             `default:"localhost:80" split_words:"true" desc:"The host to proxy to, without scheme."`
	LogFormat envtypes.LogFormat `default:"json" split_words:"true" desc:"Log formatter to use. One of json or text."`

	Issuer envtypes.Issuer `required:"true" desc:"The certificate issuer to use. One of vault, cfssl or aws."`
	Vault  envtypes.Vault
	CFSSL  envtypes.CFSSL
	AWS    envtypes.AWS

	CacheDir                  string                `split_words:"true" desc:"Directory to cache certs. If unset, will cache in memory."`
	CommonName                string                `required:"true" split_words:"true" desc:"The Common Name that will be used when issuing certificates. This can be a DNS record or a regular name."`
	RenewBefore               time.Duration         `split_words:"true" default:"4h" desc:"How long before expiry a certificate should be considered too old to use when fetched from the cache."`
	IssueTimeout              time.Duration         `default:"1m" split_words:"true"  desc:"The upper bound of time allowed per Issue request."`
	SubjectAlternativeNames   []string              `split_words:"true" desc:"A comma-separated list of DNS names that should be included in the SANs of the issued certificates."`
	IPSubjectAlternativeNames []net.IP              `envconfig:"IP_SUBJECT_ALTERNATIVE_NAMES" desc:"A comma-separated list of IPs that should be included in the IPSANs of the issued certificates."`
	KeyGenerator              envtypes.KeyGenerator `split_words:"true" default:"ecdsa" desc:"The key algorithm to use for new certificates. One of ecdsa and rsa."`
}

func main() {
	conf := configuration{}
	err := envconfig.Process("", &conf)
	if err != nil {
		_ = envconfig.Usage("", &conf)
		fmt.Println(err)
		os.Exit(1)
	}

	log := logrus.New()
	log.Formatter = conf.LogFormat

	var issuer certify.Issuer
	switch conf.Issuer {
	case envtypes.VaultIssuer:
		issuer, err = vaultIssuer(conf.Vault)
		if err != nil {
			log.WithError(err).Fatal("Failed to configure Vault issuer.")
		}
	case envtypes.CFSSLIssuer:
		issuer, err = cfsslIssuer(conf.CFSSL)
		if err != nil {
			log.WithError(err).Fatal("Failed to configure CFSSL issuer.")
		}
	case envtypes.AWSIssuer:
		issuer, err = awsIssuer(conf.AWS)
		if err != nil {
			log.WithError(err).Fatal("Failed to configure AWS issuer.")
		}
	}

	cache := certify.NewMemCache()
	if conf.CacheDir != "" {
		cache = certify.DirCache(conf.CacheDir)
	}

	c := certify.Certify{
		Issuer: issuer,
		Cache:  cache,
		Logger: logrusadapter.New(log),

		CommonName:   conf.CommonName,
		RenewBefore:  conf.RenewBefore,
		IssueTimeout: conf.IssueTimeout,
		CertConfig: &certify.CertConfig{
			SubjectAlternativeNames:   conf.SubjectAlternativeNames,
			IPSubjectAlternativeNames: conf.IPSubjectAlternativeNames,
		},
	}

	u := &url.URL{
		Scheme: "http",
		Host:   conf.ProxyAddr,
	}

	s := &http.Server{
		Addr:    conf.Addr,
		Handler: httputil.NewSingleHostReverseProxy(u),
		TLSConfig: &tls.Config{
			GetCertificate:       c.GetCertificate,
			GetClientCertificate: c.GetClientCertificate,
		},
	}

	notifyShutdown(log, s)

	log.Infof("Proxying traffic from %q to %q", conf.Addr, conf.ProxyAddr)

	err = s.ListenAndServeTLS("", "")
	if err != http.ErrServerClosed {
		log.WithError(err).Error("Failed to serve")
	}
}

func notifyShutdown(log *logrus.Logger, s *http.Server) {
	cls := make(chan os.Signal, 1)
	signal.Notify(cls, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-cls
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		defer cancel()
		err := s.Shutdown(ctx)
		if err != nil {
			log.WithError(err).Error("Failed to gracefully shut down server")
		}
	}()
}

func vaultIssuer(conf envtypes.Vault) (*vault.Issuer, error) {
	if conf.URL.String() == "" {
		return nil, errors.New("vault URL is required")
	}
	if conf.Token == "" && conf.AuthMethod == envtypes.UnknownAuthMethod {
		return nil, errors.New("vault Token or AuthMethod is required")
	}
	if conf.Role == "" {
		return nil, errors.New("vault Role is required")
	}
	v := &vault.Issuer{
		URL:                          &conf.URL,
		Role:                         conf.Role,
		Mount:                        conf.Mount,
		TimeToLive:                   conf.TimeToLive,
		URISubjectAlternativeNames:   conf.URISubjectAlternativeNames,
		OtherSubjectAlternativeNames: conf.OtherSubjectAlternativeNames,
		TLSConfig:                    &tls.Config{},
	}
	switch conf.AuthMethod {
	case envtypes.ConstantTokenAuthMethod:
		if conf.AuthMethodConstantToken == "" {
			return nil, errors.New("vault constant token is required when using the constant auth method")
		}
		v.AuthMethod = conf.AuthMethodConstantToken
	case envtypes.RenewingTokenAuthMethod:
		if conf.AuthMethodRenewingToken.Initial == "" {
			return nil, errors.New("vault initial renewing token is required when using the renewing auth method")
		}
		v.AuthMethod = &vault.RenewingToken{
			Initial:     conf.AuthMethodRenewingToken.Initial,
			RenewBefore: conf.AuthMethodRenewingToken.RenewBefore,
			TimeToLive:  conf.AuthMethodRenewingToken.TimeToLive,
		}
	default:
		v.AuthMethod = vault.ConstantToken(conf.Token)
	}
	if conf.CACertPath != "" {
		v.TLSConfig.RootCAs = x509.NewCertPool()
		bts, err := ioutil.ReadFile(conf.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA cert file: %w", err)
		}
		v.TLSConfig.RootCAs.AppendCertsFromPEM(bts)
	}

	return v, nil
}

func cfsslIssuer(conf envtypes.CFSSL) (*cfssl.Issuer, error) {
	if conf.URL.String() == "" {
		return nil, errors.New("CFSSL URL is required")
	}
	c := &cfssl.Issuer{
		URL:       &conf.URL,
		Profile:   conf.Profile,
		TLSConfig: &tls.Config{},
	}
	if conf.CACertPath != "" {
		c.TLSConfig.RootCAs = x509.NewCertPool()
		bts, err := ioutil.ReadFile(conf.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA cert file: %w", err)
		}
		c.TLSConfig.RootCAs.AppendCertsFromPEM(bts)
	}
	if conf.AuthKey != "" {
		st, err := auth.New(conf.AuthKey, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create CFSSL auth: %w", err)
		}
		c.Auth = st
	}

	return c, nil
}

func awsIssuer(conf envtypes.AWS) (*aws.Issuer, error) {
	if conf.Region == "" {
		return nil, errors.New("AWS region is required")
	}
	if conf.AccessKeyID == "" {
		return nil, errors.New("AWS access key ID is required")
	}
	if conf.AccessKeySecret == "" {
		return nil, errors.New("AWS access key secret is required")
	}
	if conf.CertificateAuthorityARN == "" {
		return nil, errors.New("AWS CA ARN is required")
	}
	ac := awssdk.Config{}
	ac.Region = conf.Region
	ac.Credentials = awssdk.CredentialsProviderFunc(func(c context.Context) (awssdk.Credentials, error) {
		return awssdk.Credentials{
			AccessKeyID:     conf.AccessKeyID,
			SecretAccessKey: conf.AccessKeySecret,
		}, nil
	})
	return &aws.Issuer{
		Client:                  acmpca.NewFromConfig(ac),
		CertificateAuthorityARN: conf.CertificateAuthorityARN,
		TimeToLive:              conf.TimeToLive,
	}, nil
}
