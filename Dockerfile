FROM golang:1.17 as build-env

COPY . /src/certify

ENV CGO_ENABLED=0

RUN cd /src/certify && go build -o /proxy ./cmd/proxy/main.go

FROM gcr.io/distroless/static

COPY --from=build-env /proxy /proxy

ENTRYPOINT ["/proxy"]
