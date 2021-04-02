GOBIN := go
GOBUILDFLAGS := -ldflags="-s -w"

build:
	mkdir -p bin
	$(GOBIN) build $(GOBUILDFLAGS) -o bin/ocs ./cli

compress:
	upx bin/ocs

prod: build compress