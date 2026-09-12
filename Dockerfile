FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod .
COPY main.go .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o codhoot-java-service .

FROM eclipse-temurin:21-jdk-alpine
WORKDIR /app
COPY --from=builder /app/codhoot-java-service .
ENV PORT=8081
EXPOSE 8081
CMD ["./codhoot-java-service"]
