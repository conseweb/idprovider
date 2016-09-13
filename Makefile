PWD := $(shell pwd)
PKG := github.com/conseweb/idprovider
# VERSION := $(shell cat VERSION.txt)
GIT_COMMIT := $(shell git rev-parse --short HEAD)
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
# LD_FLAGS := -X $(PKG)/version.version=$(VERSION) -X $(PKG)/version.gitCommit=$(GIT_COMMIT)
APP := idprovider
BUILD_CONTAINER := idprovider-$(GIT_COMMIT)
INNER_GOPATH := /opt/gopath

default: unit-test

unit-test: 
	docker run --rm \
	 --name $(UNIT_TEST_CONTAINER) \
	 -v $(PWD):$(INNER_GOPATH)/src/$(PKG) \
	 -w $(INNER_GOPATH)/src/$(PKG) \
	 ckeyer/obc:dev make testInner

testInner: 
	go test -ldflags="$(LD_FLAGS)" $$(go list ./... |grep -v "vendor"|grep -v "integration-tests")

build: 
	docker run --rm \
	 --name $(BUILD_CONTAINER) \
	 -v $(PWD):$(INNER_GOPATH)/src/$(PKG) \
	 -w $(INNER_GOPATH)/src/$(PKG) \
	 ckeyer/obc:dev go build -o bundles/$(APP) .

dev:
	docker run --rm \
	 --name $(BUILD_CONTAINER) \
	 -v $(PWD):$(INNER_GOPATH)/src/$(PKG) \
	 -w $(INNER_GOPATH)/src/$(PKG) \
	 -it ckeyer/obc:dev bash