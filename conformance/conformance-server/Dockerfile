# ---------- Stage 1: build ----------
FROM maven:3.9.9-eclipse-temurin-17 AS builder

WORKDIR /build

# 拉取最新代码
RUN git clone https://gitlab.com/openid/conformance-suite.git . --depth 1

# 构建（跳过测试可以加快速度）
RUN mvn clean package -DskipTests

# ---------- Stage 2: runtime ----------
FROM eclipse-temurin:17-jre

WORKDIR /app

# 从 builder 拷贝 jar
# 注意：jar 名字可能变，建议用通配符
COPY --from=builder /build/target/*.jar /app/fapi-test-suite.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "/app/fapi-test-suite.jar"]
