FROM golang:1.10 as build

RUN mkdir -p /go/src/github.com/uc-cdis/arborist
WORKDIR /go/src/github.com/uc-cdis/arborist
ADD . .
RUN go build -ldflags "-linkmode external -extldflags -static" -o bin/arborist

FROM scratch
COPY --from=build /go/src/github.com/uc-cdis/arborist/bin/arborist /arborist
ENTRYPOINT ["/arborist"]
