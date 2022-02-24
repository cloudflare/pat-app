COMMIT_ID=$(shell git rev-parse --short HEAD)
VERSION=$(shell cat VERSION)

NAME=pat-app

all: clean build

secrets:
	hexdump -n 32 -e '4/4 "%08X" 1 ""' /dev/urandom > client.secret

certs:
	mkcert issuer.example localhost 127.0.0.1 ::1  
	mkcert attester.example localhost 127.0.0.1 ::1
	mkcert origin.example localhost 127.0.0.1 ::1

issuer: build
	./pat-app issuer --cert issuer.example+3.pem --key issuer.example+3-key.pem --port 4567 --origins origin.example:4568 --log debug --name issuer.example:4567
origin: build
	./pat-app origin --cert origin.example+3.pem --key origin.example+3-key.pem --port 4568 --issuer issuer.example:4567 --name origin.example:4568 --log debug
attester: build
	./pat-app attester --cert attester.example+3.pem --key attester.example+3-key.pem --port 4569 --log debug

clean:
	@echo "Cleaning and removing the pat-app ..."
	@rm -f pat-app

build: clean
	@echo "Building the binary for pat-app ..."
	@echo "Tag: $(COMMIT_ID)"
	@go build -ldflags "-X main.CommitId=$(COMMIT_ID)" ./cmd/*

install:
	@go install -ldflags "-X main.CommitId=$(COMMIT_ID)" ./cmd/*

package:
	@tar -czf /tmp/pat-app.tar.gz .
	@mv /tmp/pat-app.tar.gz .

.PHONY: all clean build install