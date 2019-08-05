BIN := 4o6top
BUILD_LDFLAGS := ""
GOBIN ?= $(shell go env GOPATH)/bin

.PHONY: all
all: clean build

.PHONY: build
build:
	go build -ldflags=$(BUILD_LDFLAGS) -o $(BIN) 

.PHONY: install
install:
	go install -ldflags=$(BUILD_LDFLAGS) 

.PHONY: deps
deps:
	go get github.com/google/gopacket
	go get github.com/google/gopacket/layers
	go get github.com/google/gopacket/pcap

.PHONY: lint
lint: $(GOBIN)/golint
	go vet 
	$(GOBIN)/golint -set_exit_status 

$(GOBIN)/golint:
	go get golang.org/x/lint/golint

.PHONY: clean
clean:
	rm -rf $(BIN)
	go clean
