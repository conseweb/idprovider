#PWD := $(shell pwd)
PWD := /Users/mint/develop/gopath/src
IMAGE := mintdev:latest
INNER_GOPATH := /opt/gopath
dev:
	docker run --rm \
	 --name idproviderdev \
	 -v $(PWD):$(INNER_GOPATH)/src \
	 -w $(INNER_GOPATH)/src \
	 -v /var/run/docker.sock:/var/run/docker.sock \
	 -it $(IMAGE) zsh