BIN := 4o6top
GOBIN ?= $(shell go env GOPATH)/bin

NAME    :=4o6top
VERSION := 0.2
MINVER  :=$(shell date -u +.%Y%m%d)
BUILD_LDFLAGS := "-X main.Name=$(NAME) -X main.Version=$(VERSION)$(MINVER)" 

.PHONY: all
all: clean build

.PHONY: build
build:
	GO111MODULE=on go build -ldflags=$(BUILD_LDFLAGS) -o $(BIN) 

.PHONY: install
install:
	go install -ldflags=$(BUILD_LDFLAGS) 

.PHONY: lint
lint: $(GOBIN)/golint
	go fmt
	go vet 
	$(GOBIN)/golint -set_exit_status 

$(GOBIN)/golint:
	go get golang.org/x/lint/golint

.PHONY: clean
clean:
	rm -rf $(BIN)
	go clean
