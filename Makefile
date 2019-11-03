BUILD_DATE=$(shell date "+%F_%T_%Z")
BUILD_COMMIT_ID=$(shell git rev-parse --short=8 HEAD)
VERPKG=main
LDFLAGS=-s -w -X $(VERPKG).buildDate=$(BUILD_DATE) -X $(VERPKG).buildCommitID=$(BUILD_COMMIT_ID)

export GO111MODULE=on
export CGO_ENABLED=0

all: tls-proxy-freebsd-amd64

tls-proxy-freebsd-amd64: *.go
	GOOS=freebsd GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $@

clean:
	rm -f tls-proxy-freebsd-amd64