patch:
	go mod vendor
	cp wasm/util_unix.go.patched vendor/github.com/in-toto/in-toto-golang/in_toto/util_unix.go

build:
	GOOS=js GOARCH=wasm go build -trimpath -ldflags= -o wasm/tinfoil-verifier.wasm ./wasm/...
	#cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" .
