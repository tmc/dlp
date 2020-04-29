FROM golang:1.14-buster

WORKDIR /build
COPY go.mod go.sum .
RUN go mod download -x

COPY . .
RUN go install -v ./...

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
