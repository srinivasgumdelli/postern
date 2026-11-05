# syntax=docker/dockerfile:1

# Builder: pinned Go toolchain (tag and digest).
FROM golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61 AS build
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
