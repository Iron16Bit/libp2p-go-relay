# libp2p P2P Relay

## Building

export GO111MODULE=on
go env -w GOPROXY=https://proxy.golang.org,direct

go get github.com/libp2p/go-libp2p@latest

go mod tidy
go build -v -o relay main.go