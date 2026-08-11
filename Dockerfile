# Build stage
FROM golang:1.26-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /out/goleanauth ./cmd

# Runtime stage
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata && adduser -D -u 10001 appuser
COPY --from=build /out/goleanauth /usr/local/bin/goleanauth
COPY .env.example /app/.env.example
USER appuser
WORKDIR /app
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/goleanauth"]
