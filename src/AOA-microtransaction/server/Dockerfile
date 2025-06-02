# server/Dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o /server main.go

FROM alpine:3.18
RUN apk add --no-cache ca-certificates
WORKDIR /root/
COPY --from=builder /server .
# Копируем TLS-сертификаты в контейнер
#COPY ../certs/server.crt /certs/server.crt
COPY ../certs/server.key /certs/server.key

EXPOSE 50051
ENTRYPOINT ["./server"]
CMD ["-cert", "/certs/server.crt", "-key", "/certs/server.key"]
