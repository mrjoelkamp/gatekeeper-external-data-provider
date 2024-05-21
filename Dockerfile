ARG BUILDPLATFORM="linux/amd64"
ARG BUILDERIMAGE="golang:1.22"
ARG BASEIMAGE="gcr.io/distroless/static:nonroot"

FROM --platform=${BUILDPLATFORM} ${BUILDERIMAGE} as builder

ARG TARGETPLATFORM
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT=""
ARG LDFLAGS

ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH} \
    GOARM=${TARGETVARIANT}

WORKDIR /go/src/github.com/open-policy-agent/gatekeeper-external-data-provider

COPY . .

# This block can be replaced by `RUN go mod download` when github.com/docker/attest is public
ENV GOPRIVATE="github.com/docker/attest"
RUN --mount=type=secret,id=GITHUB_TOKEN <<EOT
  set -e
  GITHUB_TOKEN=${GITHUB_TOKEN:-$(cat /run/secrets/GITHUB_TOKEN)}
  if [ -n "$GITHUB_TOKEN" ]; then
    echo "Setting GitHub access token"
    git config --global "url.https://x-access-token:${GITHUB_TOKEN}@github.com.insteadof" "https://github.com"
  fi
  go mod download
EOT
RUN make build

FROM ${BASEIMAGE}

WORKDIR /tuf

COPY --from=builder /go/src/github.com/open-policy-agent/gatekeeper-external-data-provider/bin/attest .

COPY --from=builder --chown=65532:65532 /go/src/github.com/open-policy-agent/gatekeeper-external-data-provider/certs/tls.crt \
    /go/src/github.com/open-policy-agent/gatekeeper-external-data-provider/certs/tls.key \
    /certs/

USER 65532:65532

ENTRYPOINT ["/tuf/attest"]
