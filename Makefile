patch:
	go mod vendor
	cp wasm/util_unix.go.patched vendor/github.com/in-toto/in-toto-golang/in_toto/util_unix.go

build:
	docker build -t tinfoil-verifier-builder .
	docker run --rm -v $(shell pwd):/src tinfoil-verifier-builder
	#cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" .
