GOENV := CGO_ENABLED=0
GOBIN := $(GOENV) go
GOBUILDFLAGS := -ldflags="-s -w"

DOCKER_REPO := tcfw
DOCKER_TAG := latest
DOCKER_CMD := docker
DOCKER_BUILD_CMD := $(DOCKER_CMD) build

GIT_COMMIT := $(shell git log -1 --format=%h)

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

clean:
	rm ./bin/*

deep-clean: clean
	go clean -cache -testcache

docker:
	$(DOCKER_BUILD_CMD) --build-arg GIT_COMMIT=$(GIT_COMMIT) --build-arg VERSION=$(VERSION) -t $(DOCKER_REPO)/ocs-cdi:$(DOCKER_TAG) . 