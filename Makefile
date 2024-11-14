patch:
	go mod vendor
	cp wasm/util_unix.go.patched vendor/github.com/in-toto/in-toto-golang/in_toto/util_unix.go

build:
	GOOS=js GOARCH=wasm go build -trimpath -ldflags=-buildid= -o wasm/tinfoil-verifier.wasm ./wasm/...
	sha256sum wasm/tinfoil-verifier.wasm
	#cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" .

test:
	go test ./...
