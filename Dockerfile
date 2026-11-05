# syntax=docker/dockerfile:1

# Builder: pinned Go toolchain (tag and digest).
FROM golang:1.27.3-bookworm@sha256:d9b6a1beb9474adc2a1ce842573639b44b2a0dd49b6669f51d3821baf9ec37c9 AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-mod=readonly GOTOOLCHAIN=local
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/postern-relay ./cmd/postern-relay
COPY internal ./internal
RUN go build -trimpath -ldflags "-s -w" -o /out/postern-relay ./cmd/postern-relay \
 && mkdir -p /out/data \
 && chmod 0700 /out/data

# Runtime: distroless static, non-root (uid/gid 65532), no shell.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/postern-relay /usr/local/bin/postern-relay
# A new named volume mounted at /data inherits this owner and mode.
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/postern-relay"]
CMD ["-config", "/etc/postern/relay.json"]
