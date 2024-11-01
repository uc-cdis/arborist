FROM quay.io/cdis/golang:1.17-bullseye AS build-deps

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

FROM scratch
COPY --from=build-deps /etc_passwd /etc/passwd
COPY --from=build-deps /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build-deps $GOPATH/src/github.com/uc-cdis/arborist/ /arborist
USER nobody
CMD ["/arborist/migrations/latest", "&&", "/arborist/bin/arborist", "-port", "8080"]
