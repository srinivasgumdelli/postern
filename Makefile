GO ?= go
BIN := bin

.PHONY: build test race vet keychain-test presence-test relay-image clean

build:
	$(GO) build -trimpath -o $(BIN)/postern ./cmd/postern
	$(GO) build -trimpath -o $(BIN)/postern-relay ./cmd/postern-relay

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...
	@test -z "$$(gofmt -l .)" || (gofmt -l . && echo "gofmt needed" && exit 1)

# Touches the real login keychain with a throwaway service name.
keychain-test:
	POSTERN_TEST_KEYCHAIN=1 $(GO) test -count=1 ./internal/secrets/...

# Shows the real Touch ID / login password dialog; approve it.
presence-test:
	POSTERN_TEST_PRESENCE=1 $(GO) test -count=1 -run TestRealPresence -v ./internal/presence/

relay-image:
	docker compose build relay

clean:
	rm -rf $(BIN)
