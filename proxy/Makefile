.PHONY: build test lint fmt vet clean

BINARY := bin/mithril-proxy

build:
	CGO_ENABLED=0 go build -o $(BINARY) .

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l .

lint: fmt vet

clean:
	rm -rf bin

run: build
	./$(BINARY)
