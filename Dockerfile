FROM golang:latest AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o carsgo ./cmd/*.go
FROM alpine:3.18
WORKDIR /root/
COPY --from=builder /app/carsgo .
COPY /cmd/.env .env  
EXPOSE 10010
CMD ["./carsgo"]