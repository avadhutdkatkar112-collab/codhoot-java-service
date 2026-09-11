FROM eclipse-temurin:21-jdk-jammy

WORKDIR /app
COPY codhoot-java-service .

ENV PORT=8081
EXPOSE 8081

CMD ["./codhoot-java-service"]
