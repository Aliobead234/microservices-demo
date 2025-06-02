# client/Dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o /client main.go

FROM alpine:3.18
RUN apk add --no-cache ca-certificates
WORKDIR /root/
COPY --from=builder /client .
# Копируем сертификаты CA и приватный ключ клиента
#COPY ../certs/ca.crt /certs/ca.crt
COPY ../certs/client.key /certs/client.key

ENTRYPOINT ["./client"]
