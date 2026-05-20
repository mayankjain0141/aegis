FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /aegis ./cmd/aegis
RUN CGO_ENABLED=0 go build -o /aegis-hook ./cmd/hook

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /aegis /usr/local/bin/aegis
COPY --from=builder /aegis-hook /usr/local/bin/aegis-hook
COPY policies/ /etc/aegis/policies/
ENTRYPOINT ["aegis"]
CMD ["daemon", "run"]
