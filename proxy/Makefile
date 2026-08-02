.PHONY: build test lint fmt vet clean generate

BINARY := bin/mithril-proxy

# eBPF Go bindings (proxy/ebpf/sockops/*_bpfel.go, *_bpfeb.go) are
# generated, not committed (see .gitignore) — `build`/`test` will fail
# on a fresh clone until `make generate` has been run once. Requires
# clang, bpftool, and go's bpf2go tool; bpftool lives in /usr/sbin
# which isn't on a normal user's PATH by default.
generate:
	PATH="$$HOME/go/bin:/usr/sbin:$$PATH" BPF2GO_STRIP=/usr/bin/llvm-strip-19 go generate ./...

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
