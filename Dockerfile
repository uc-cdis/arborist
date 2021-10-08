FROM quay.io/cdis/golang:1.17-bullseye as build-deps

ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64

WORKDIR $GOPATH/src/github.com/uc-cdis/arborist/

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

RUN go build -o /arborist

FROM scratch
COPY --from=build-deps /arborist /arborist
CMD ["/arborist"]
