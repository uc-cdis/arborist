FROM quay.io/cdis/golang:1.17-bullseye as build-deps

ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64

RUN apt-get update \
    && apt-get install -y --no-install-recommends postgresql=13.* \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR $GOPATH/src/github.com/uc-cdis/arborist/

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

RUN go build -o /arborist

CMD ["/arborist"]
