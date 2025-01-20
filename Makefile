clean:
	rm -rf TinfoilVerifier.xcframework wasm/tinfoil-verifier.wasm vendor

wasm-patch: # This is a hack. We should upstream this
	go mod vendor
	cp wasm/util_unix.go.patched vendor/github.com/in-toto/in-toto-golang/in_toto/util_unix.go

wasm-build: wasm-patch
	GOOS=js GOARCH=wasm go build \
		-trimpath \
		-ldflags=-buildid= \
		-o wasm/tinfoil-verifier.wasm \
		./wasm/...
	#cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" .

ios-bind:
	go get golang.org/x/mobile/cmd/gomobile
	gomobile bind -target=ios -o TinfoilVerifier.xcframework github.com/tinfoilanalytics/verifier/pkg/client
	go mod tidy

build: clean ios-bind wasm-build
