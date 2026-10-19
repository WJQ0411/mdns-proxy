# Build stage
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache libpcap-dev gcc musl-dev

WORKDIR /build

COPY . .
RUN go mod tidy && CGO_ENABLED=1 go build -o mdns-proxy .

# Final stage
FROM alpine:3.24

RUN apk add --no-cache libpcap

COPY --from=builder /build/mdns-proxy /usr/local/bin/mdns-proxy

ENTRYPOINT ["/usr/local/bin/mdns-proxy"]
