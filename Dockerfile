FROM quay.io/cdis/golang:1.22-bullseye AS build-deps

ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64

RUN apt-get update \
    && apt-get install -y --no-install-recommends jq=1.* postgresql=13* \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR $GOPATH/src/github.com/uc-cdis/arborist/

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

RUN GITCOMMIT=$(git rev-parse HEAD) \
    GITVERSION=$(git describe --always --tags) \
    && go build \
    -ldflags="-X 'github.com/uc-cdis/arborist/arborist/version.GitCommit=${GITCOMMIT}' -X 'github.com/uc-cdis/arborist/arborist/version.GitVersion=${GITVERSION}'" \
    -o bin/arborist

RUN echo "nobody:x:65534:65534:Nobody:/:" > /etc_passwd

FROM quay.io/cdis/golang-build-base:master
RUN dnf update \
        --assumeyes \
    && dnf install \
        --assumeyes \
        --setopt=install_weak_deps=False \
        --setopt=tsflags=nodocs \
        postgresql15 \
        jq \ 
    && dnf clean all \
    && rm -rf /var/cache/yum
COPY --from=build-deps /etc_passwd /etc/passwd
COPY --from=build-deps /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build-deps /go/src/github.com/uc-cdis/arborist/ /go/src/github.com/uc-cdis/arborist/
RUN setcap 'cap_net_bind_service=+ep' /go/src/github.com/uc-cdis/arborist/bin/arborist
WORKDIR /go/src/github.com/uc-cdis/arborist/
USER nobody
CMD ["/go/src/github.com/uc-cdis/arborist/bin/arborist"]
