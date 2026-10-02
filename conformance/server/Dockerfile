# ---------- Stage 1: build ----------
FROM maven:3.9.9-eclipse-temurin-21 AS builder

WORKDIR /build

ARG SUITE_REF=master
RUN git init . \
    && git remote add origin https://gitlab.com/openid/conformance-suite.git \
    && git fetch --depth 1 origin "$SUITE_REF" \
    && git checkout --detach FETCH_HEAD \
    && git rev-parse HEAD > /build/suite-revision.txt

RUN mvn clean package -DskipTests

# ---------- Stage 2: runtime ----------
FROM eclipse-temurin:21-jre

WORKDIR /app

COPY --from=builder /build/target/*.jar /app/fapi-test-suite.jar
COPY --from=builder /build/suite-revision.txt /app/suite-revision.txt

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "/app/fapi-test-suite.jar"]
