# syntax=docker/dockerfile:1
#
# Build and runtime are both on the hardened Amazon Linux base (FIPS crypto
# policy). The Go toolchain is a sha256-pinned go.dev release and the binary is
# compiled against the Go Cryptographic Module (GOFIPS140).

ARG AZLINUX_BASE_VERSION=hardened

# ------ Build stage ------
FROM quay.io/cdis/amazonlinux-base:${AZLINUX_BASE_VERSION} AS build

ARG TARGETOS
ARG TARGETARCH
ARG GO_VERSION=1.26.4
ARG GO_SHA256_AMD64=1153d3d50e0ac764b447adfe05c2bcf08e889d42a02e0fe0259bd47f6733ad7f
ARG GO_SHA256_ARM64=ef758ae7c6cf9267c9c0ef080b8965f453d89ab2d25d9eb22de4405925238768

RUN dnf -y install --nodocs --setopt=install_weak_deps=False git tar gzip && \
    dnf clean all

RUN case "${TARGETARCH}" in \
        amd64) sha="${GO_SHA256_AMD64}" ;; \
        arm64) sha="${GO_SHA256_ARM64}" ;; \
        *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac && \
    curl -fsSL -o /tmp/go.tgz "https://go.dev/dl/go${GO_VERSION}.linux-${TARGETARCH}.tar.gz" && \
    echo "${sha}  /tmp/go.tgz" | sha256sum -c - && \
    tar -C /usr/local -xzf /tmp/go.tgz && rm /tmp/go.tgz

ENV PATH="/usr/local/go/bin:${PATH}" \
    CGO_ENABLED=0 \
    GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH} \
    GOTOOLCHAIN=local \
    GOFLAGS=-mod=readonly \
    GOFIPS140=v1.0.0

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

RUN GITCOMMIT=$(git rev-parse HEAD) && \
    GITVERSION=$(git describe --always --tags) && \
    go build -trimpath \
        -ldflags="-s -w -X 'github.com/uc-cdis/arborist/arborist/version.GitCommit=${GITCOMMIT}' -X 'github.com/uc-cdis/arborist/arborist/version.GitVersion=${GITVERSION}'" \
        -o /out/arborist && \
    /out/arborist --help >/dev/null 2>&1

# ------ Runtime stage ------
# Paths are unchanged from the previous image so the gen3-helm chart works as-is:
# it runs migrations/latest (bash + psql) and then bin/arborist from this dir.
FROM quay.io/cdis/amazonlinux-base:${AZLINUX_BASE_VERSION}

ENV appdir=/go/src/github.com/uc-cdis/arborist
WORKDIR ${appdir}

COPY --from=build /out/arborist ${appdir}/bin/arborist
COPY --from=build /src/migrations ${appdir}/migrations
COPY --from=build /src/jobs ${appdir}/jobs

# psql is required by migrations/ and jobs/. setcap (libcap, already in the
# base) lets the binary bind :80 as a non-root user; everything that can
# fetch, build, or install code is removed. rpm-libs stays (other packages
# link it); only the rpm executable package goes.
RUN dnf -y update && \
    dnf -y install --nodocs --setopt=install_weak_deps=False postgresql15 && \
    dnf clean all && \
    /usr/sbin/setcap 'cap_net_bind_service=+ep' ${appdir}/bin/arborist && \
    dnf -y remove --setopt=protected_packages= --setopt=clean_requirements_on_remove=False \
        dnf yum python3-dnf && \
    rpm -e --nodeps python3 $(rpm -qa 'python3-*') curl-minimal rpm && \
    rm -rf /usr/lib/python3.9 /usr/lib64/python3.9 /var/cache/dnf /var/tmp/dnf* /tmp/*

USER nobody
CMD ["/go/src/github.com/uc-cdis/arborist/bin/arborist"]
