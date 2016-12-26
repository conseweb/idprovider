PWD := $(shell pwd)
PKG := github.com/conseweb/idprovider
OS := $(shell go env GOOS)-$(shell go env GOARCH)
VERSION := $(shell cat VERSION.txt)
GIT_COMMIT := $(shell git rev-parse --short HEAD)
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
# LD_FLAGS := -X $(PKG)/version.version=$(VERSION) -X $(PKG)/version.gitCommit=$(GIT_COMMIT)
APP := idprovider
BUILD_CONTAINER := idprovider-$(GIT_COMMIT)
INNER_GOPATH := /opt/gopath

NET := $(shell docker network inspect cknet > /dev/zero && echo "--net cknet --ip 172.16.1.3" || echo "")

default: unit-test

unit-test: 
	docker run --rm \
	 --name $(UNIT_TEST_CONTAINER) \
	 -v $(PWD):$(INNER_GOPATH)/src/$(PKG) \
	 -w $(INNER_GOPATH)/src/$(PKG) \
	 ckeyer/obc:dev make testInner

testInner: 
	go test -ldflags="$(LD_FLAGS)" $$(go list ./... |grep -v "vendor"|grep -v "integration-tests")

default:
	echo "hello$(NET)"

release: clean local
	cd bundles && tar zcf $(APP)-$(OS).$(VERSION).tgz $(APP)

local:
	go build -v -o bundles/$(APP) .
	echo "build Successful"

clean:
	-rm -rf bundles

build: 
	docker run --rm \
	 --name $(BUILD_CONTAINER) \
	 -v $(PWD):$(INNER_GOPATH)/src/$(PKG) \
	 -w $(INNER_GOPATH)/src/$(PKG) \
	 ckeyer/obc:dev go build -v -o bundles/$(APP) .

build-image: #build
	docker build -t conseweb/$(APP):$(GIT_BRANCH) .

dev:
	docker run --rm \
	 $(NET) \
	 --name $(BUILD_CONTAINER) \
	 -v $(PWD):$(INNER_GOPATH)/src/$(PKG) \
	 -w $(INNER_GOPATH)/src/$(PKG) \
	 -it ckeyer/obc:dev bash