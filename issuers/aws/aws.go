package aws

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	"github.com/aws/aws-sdk-go-v2/service/acmpca/types"

	"github.com/johanbrandhorst/certify"
	"github.com/johanbrandhorst/certify/internal/csr"
)

// Issuer implements the Issuer interface with a
// AWS Certificate Manager Private Certificate Authority backend.
//
// Client and CertificateAuthorityARN are required.
type Issuer struct {
	// Client is a pre-created ACMPCA client. It can be created
	// via, for example:
	//    conf, err := external.LoadDefaultAWSConfig()
	//    if err != nil {
	//        return nil, err
	//    }
	//    conf.Region = endpoints.EuWest2RegionID
	//    conf.Credentials = aws.NewStaticCredentialsProvider("YOURKEY", "YOURKEYSECRET", "")
	//    cli := acmpca.New(conf)
	Client *acmpca.Client
	// CertificateAuthorityARN specifies the ARN of a pre-created CA
	// which will be used to issue the certificates.
	CertificateAuthorityARN string

	// TimeToLive configures the lifetime of certificates
	// requested from the AWS CA, in number of days.
	// If unset, defaults to 30 days.
	TimeToLive int

	initOnce sync.Once
	initErr  error
	caCert   *x509.Certificate
	signAlgo types.SigningAlgorithm
	waiter   *acmpca.CertificateIssuedWaiter
}

// Issue issues a certificate from the configured AWS CA backend.
func (i Issuer) Issue(ctx context.Context, commonName string, conf *certify.CertConfig) (*tls.Certificate, error) {
	i.initOnce.Do(func() {
		i.waiter = acmpca.NewCertificateIssuedWaiter(i.Client)

		caResp, err := i.Client.GetCertificateAuthorityCertificate(ctx, &acmpca.GetCertificateAuthorityCertificateInput{
			CertificateAuthorityArn: aws.String(i.CertificateAuthorityARN),
		})
		if err != nil {
			i.initErr = err
			return
		}

		caBlock, _ := pem.Decode([]byte(*caResp.Certificate))
		if caBlock == nil {
			i.initErr = errors.New("could not parse AWS CA cert")
			return
		}

		if caBlock.Type != "CERTIFICATE" {
			i.initErr = errors.New("saw unexpected PEM Type while requesting AWS CA cert: " + caBlock.Type)
			return
		}

		i.caCert, err = x509.ParseCertificate(caBlock.Bytes)
		if err != nil {
			i.initErr = err
			return
		}

		switch i.caCert.SignatureAlgorithm {
		case x509.SHA256WithRSA:
			i.signAlgo = types.SigningAlgorithmSha256withrsa
		case x509.SHA384WithRSA:
			i.signAlgo = types.SigningAlgorithmSha384withrsa
		case x509.SHA512WithRSA:
			i.signAlgo = types.SigningAlgorithmSha512withrsa
		case x509.ECDSAWithSHA256:
			i.signAlgo = types.SigningAlgorithmSha256withecdsa
		case x509.ECDSAWithSHA384:
			i.signAlgo = types.SigningAlgorithmSha384withecdsa
		case x509.ECDSAWithSHA512:
			i.signAlgo = types.SigningAlgorithmSha512withecdsa
		default:
			i.initErr = fmt.Errorf("unsupported CA cert signing algorithm: %T", i.caCert.SignatureAlgorithm)
			return
		}
	})
	if i.initErr != nil {
		return nil, i.initErr
	}

	csrPEM, keyPEM, err := csr.FromCertConfig(commonName, conf)
	if err != nil {
		return nil, err
	}

	// Default to 30 days if unset.
	ttl := int64(30)
	if i.TimeToLive > 0 {
		ttl = int64(i.TimeToLive)
	}

	issueResp, err := i.Client.IssueCertificate(ctx, &acmpca.IssueCertificateInput{
		CertificateAuthorityArn: aws.String(i.CertificateAuthorityARN),
		Csr:                     csrPEM,
		SigningAlgorithm:        i.signAlgo,
		Validity: &types.Validity{
			Type:  types.ValidityPeriodTypeDays,
			Value: aws.Int64(ttl),
		},
	})
	if err != nil {
		return nil, err
	}

	err = i.waiter.Wait(ctx, &acmpca.GetCertificateInput{
		CertificateArn:          issueResp.CertificateArn,
		CertificateAuthorityArn: aws.String(i.CertificateAuthorityARN),
	}, time.Minute)
	if err != nil {
		return nil, err
	}

	getReq := &acmpca.GetCertificateInput{
		CertificateArn:          issueResp.CertificateArn,
		CertificateAuthorityArn: aws.String(i.CertificateAuthorityARN),
	}

	cert, err := i.Client.GetCertificate(ctx, getReq)
	if err != nil {
		return nil, err
	}

	caChainPEM := append(append([]byte(*cert.Certificate), '\n'), []byte(*cert.CertificateChain)...)

	tlsCert, err := tls.X509KeyPair(caChainPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	// This can't error since it's called in tls.X509KeyPair above successfully
	tlsCert.Leaf, _ = x509.ParseCertificate(tlsCert.Certificate[0])
	return &tlsCert, nil
}
