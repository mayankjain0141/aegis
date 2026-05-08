FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /aegis-daemon ./cmd/daemon

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /aegis-daemon /usr/local/bin/aegis-daemon
COPY policies/ /etc/aegis/policies/
COPY aegis.yaml /etc/aegis/aegis.yaml
ENTRYPOINT ["aegis-daemon"]
CMD ["--socket", "/tmp/aegis.sock", "--policies", "/etc/aegis/policies/default.yaml", "--config", "/etc/aegis/aegis.yaml"]
