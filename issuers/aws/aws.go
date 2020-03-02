package aws

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	iface "github.com/aws/aws-sdk-go-v2/service/acmpca/acmpcaiface"

	"github.com/johanbrandhorst/certify"
	"github.com/johanbrandhorst/certify/ext/csr"
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
	Client iface.ACMPCAAPI
	// CertificateAuthorityARN specifies the ARN of a pre-created CA
	// which will be used to issue the certificates.
	CertificateAuthorityARN string

	// TimeToLive configures the lifetime of certificates
	// requested from the AWS CA, in number of days.
	// If unset, defaults to 30 days.
	TimeToLive int

	caCert   *x509.Certificate
	signAlgo acmpca.SigningAlgorithm
}

// Issue issues a certificate from the configured AWS CA backend.
func (i Issuer) Issue(ctx context.Context, commonName string, conf *certify.CertConfig) (*tls.Certificate, error) {
	if i.caCert == nil {
		caReq := i.Client.GetCertificateAuthorityCertificateRequest(&acmpca.GetCertificateAuthorityCertificateInput{
			CertificateAuthorityArn: aws.String(i.CertificateAuthorityARN),
		})

		caResp, err := caReq.Send()
		if err != nil {
			return nil, err
		}

		caBlock, _ := pem.Decode([]byte(*caResp.Certificate))
		if caBlock == nil {
			return nil, errors.New("could not parse AWS CA cert")
		}

		if caBlock.Type != "CERTIFICATE" {
			return nil, errors.New("saw unexpected PEM Type while requesting AWS CA cert: " + caBlock.Type)
		}

		i.caCert, err = x509.ParseCertificate(caBlock.Bytes)
		if err != nil {
			return nil, err
		}

		switch i.caCert.SignatureAlgorithm {
		case x509.SHA256WithRSA:
			i.signAlgo = acmpca.SigningAlgorithmSha256withrsa
		case x509.SHA384WithRSA:
			i.signAlgo = acmpca.SigningAlgorithmSha384withrsa
		case x509.SHA512WithRSA:
			i.signAlgo = acmpca.SigningAlgorithmSha512withrsa
		case x509.ECDSAWithSHA256:
			i.signAlgo = acmpca.SigningAlgorithmSha256withecdsa
		case x509.ECDSAWithSHA384:
			i.signAlgo = acmpca.SigningAlgorithmSha384withecdsa
		case x509.ECDSAWithSHA512:
			i.signAlgo = acmpca.SigningAlgorithmSha512withecdsa
		default:
			return nil, fmt.Errorf("unsupported CA cert signing algorithm: %T", i.caCert.SignatureAlgorithm)
		}
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

	csrReq := i.Client.IssueCertificateRequest(&acmpca.IssueCertificateInput{
		CertificateAuthorityArn: aws.String(i.CertificateAuthorityARN),
		Csr:                     csrPEM,
		SigningAlgorithm:        i.signAlgo,
		Validity: &acmpca.Validity{
			Type:  acmpca.ValidityPeriodTypeDays,
			Value: aws.Int64(ttl),
		},
	})

	csrResp, err := csrReq.Send()
	if err != nil {
		return nil, err
	}

	getReq := &acmpca.GetCertificateInput{
		CertificateArn:          csrResp.CertificateArn,
		CertificateAuthorityArn: aws.String(i.CertificateAuthorityARN),
	}
	err = i.Client.WaitUntilCertificateIssuedWithContext(ctx, getReq)
	if err != nil {
		return nil, err
	}

	certReq := i.Client.GetCertificateRequest(getReq)

	certResp, err := certReq.Send()
	if err != nil {
		return nil, err
	}

	caChainPEM := append(append([]byte(*certResp.Certificate), '\n'), []byte(*certResp.CertificateChain)...)

	tlsCert, err := tls.X509KeyPair(caChainPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	// This can't error since it's called in tls.X509KeyPair above successfully
	tlsCert.Leaf, _ = x509.ParseCertificate(tlsCert.Certificate[0])
	return &tlsCert, nil
}
