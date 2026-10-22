# make node                         all protocols for this machine
# make node PROTOCOLS=anytls        AnyTLS only
# make node-linux PROTOCOLS=anytls,vless   linux amd64 + arm64 into bin/
comma := ,
PROTOCOLS ?= anytls,vless,ss
# VLESS Vision needs sing-vmess built with_utls to recognize Reality connections.
TAGS := $(PROTOCOLS)$(if $(findstring vless,$(PROTOCOLS)),$(comma)with_utls)
SUFFIX := $(subst $(comma),-,$(PROTOCOLS))
GOFLAGS_BUILD := -trimpath -ldflags "-s -w -buildid=" -tags "$(TAGS)"

.PHONY: node node-linux test compat limits

node:
	CGO_ENABLED=0 go build $(GOFLAGS_BUILD) -o bin/keel-node-$(SUFFIX) ./cmd/keel-node

node-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(GOFLAGS_BUILD) -o bin/keel-node-$(SUFFIX)-linux-amd64 ./cmd/keel-node
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(GOFLAGS_BUILD) -o bin/keel-node-$(SUFFIX)-linux-arm64 ./cmd/keel-node

test:
	go test -race -tags anytls,vless,with_utls,ss ./...

# Client compatibility and limit tests; BIN must point at xray-*/mihomo/sing-box.
compat:
	test/compat/run.sh
limits:
	test/compat/limits.sh
