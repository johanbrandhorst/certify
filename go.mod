module github.com/johanbrandhorst/certify

go 1.16

require (
	github.com/aws/aws-sdk-go-v2 v1.16.4
	github.com/aws/aws-sdk-go-v2/service/acmpca v1.17.7
	github.com/cloudflare/cfssl v1.6.1
	github.com/golang/protobuf v1.5.2
	github.com/hashicorp/vault/api v1.6.0
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/onsi/ginkgo v1.16.5
	github.com/onsi/gomega v1.19.0
	github.com/ory/dockertest/v3 v3.8.1
	github.com/sirupsen/logrus v1.8.1
	github.com/spiffe/go-spiffe v1.1.0
	golang.org/x/sync v0.0.0-20220513210516-0976fa681c29
	google.golang.org/grpc v1.46.2
	google.golang.org/protobuf v1.28.0
	logur.dev/adapter/logrus v0.5.0
)
