GOENV := CGO_ENABLED=0
GOBIN := $(GOENV) go
GOBUILDFLAGS := -ldflags="-s -w"

build: build-ocs build-cdi

build-ocs:
	@mkdir -p bin
	$(GOBIN) build $(GOBUILDFLAGS) -o bin/ocs ./cli

build-cdi:
	@mkdir -p bin
	$(GOBIN) build $(GOBUILDFLAGS) -o bin/ocs-cdi ./cdi/cmd

compress:
	upx bin/*

release: build compress