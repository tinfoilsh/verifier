FROM golang:1.23.3-alpine3.20

WORKDIR /src

RUN apk add make

ENV GOOS=js
ENV GOARCH=wasm

ENTRYPOINT ["sh", "-c", "go build -trimpath -ldflags=-buildid= -o wasm/tinfoil-verifier.wasm ./wasm/... && sha256sum wasm/tinfoil-verifier.wasm"]
