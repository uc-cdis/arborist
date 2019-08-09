FROM golang:1.12-alpine as build

# Install SSL certificates
RUN apk update && apk add --no-cache git ca-certificates gcc musl-dev jq curl bash postgresql

# Build static arborist binary
RUN mkdir -p /go/src/github.com/uc-cdis/arborist
WORKDIR /go/src/github.com/uc-cdis/arborist
ADD . .
RUN go get golang.org/x/tools/cmd/goyacc
RUN goyacc -o arborist/resource_rules.go arborist/resource_rules.y
RUN go build -ldflags "-linkmode external -extldflags -static" -o bin/arborist

ENTRYPOINT ["bin/arborist"]
