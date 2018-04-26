FROM golang:1.10 as build

WORKDIR /arborist

ENV GOPATH=/arborist

COPY . /arborist

RUN go get ./ && go build -o /arborist/bin/arborist -ldflags "-linkmode external -extldflags -static"

FROM scratch
COPY --from=build /arborist/bin/arborist /arborist
CMD ["/arborist"]
