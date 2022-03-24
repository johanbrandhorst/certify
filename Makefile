.PHONY: generate
generate:
	buf generate

.PHONY: install
install:
	go install github.com/bufbuild/buf/cmd/buf@v1.1.1
	go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28.0
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.1.0
