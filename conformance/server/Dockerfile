# ---------- Stage 1: build ----------
FROM maven:3.9.9-eclipse-temurin-21 AS builder

WORKDIR /build

RUN git clone https://gitlab.com/openid/conformance-suite.git . --depth 1

RUN mvn clean package -DskipTests

# ---------- Stage 2: runtime ----------
FROM eclipse-temurin:21-jre

WORKDIR /app

COPY --from=builder /build/target/*.jar /app/fapi-test-suite.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "/app/fapi-test-suite.jar"]
