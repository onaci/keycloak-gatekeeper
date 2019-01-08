FROM golang:1.11.1-alpine3.7 AS builder
RUN apk add --no-cache git gcc musl-dev

ADD https://github.com/golang/dep/releases/download/v0.5.0/dep-linux-amd64 /usr/bin/dep
RUN chmod +x /usr/bin/dep

WORKDIR /go/src/github.com/keycloak/keycloak-gatekeeper
COPY ./Gopkg.toml ./Gopkg.lock ./
RUN dep ensure --vendor-only
COPY ./ ./
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo .

FROM alpine:3.7

LABEL Name=keycloak-gatekeeper \
      Release=https://github.com/keycloak/keycloak-gatekeeper \
      Url=https://github.com/keycloak/keycloak-gatekeeper \
      Help=https://github.com/keycloak/keycloak-gatekeeper/issues

RUN apk add --no-cache ca-certificates

COPY --from=builder /go/src/github.com/keycloak/keycloak-gatekeeper/keycloak-gatekeeper /opt/keycloak-gatekeeper
ADD templates/ /opt/templates
WORKDIR "/opt"

ENTRYPOINT [ "/opt/keycloak-gatekeeper" ]
