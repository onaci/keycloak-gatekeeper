FROM golang:alpine3.11 AS builder
RUN apk add --no-cache git gcc musl-dev

WORKDIR /go/src/github.com/keycloak/keycloak-gatekeeper
COPY ./go.mod ./go.sum ./
RUN go mod download
COPY ./ ./
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo .

FROM alpine:3.11

LABEL Name=keycloak-gatekeeper \
      Release=https://github.com/keycloak/keycloak-gatekeeper \
      Url=https://github.com/keycloak/keycloak-gatekeeper \
      Help=https://github.com/keycloak/keycloak-gatekeeper/issues

RUN apk add --no-cache ca-certificates

COPY --from=builder /go/src/github.com/keycloak/keycloak-gatekeeper/keycloak-gatekeeper /opt/keycloak-gatekeeper
ADD templates/ /opt/templates
WORKDIR "/opt"

ENTRYPOINT [ "/opt/keycloak-gatekeeper" ]
