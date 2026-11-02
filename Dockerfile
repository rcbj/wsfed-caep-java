# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
FROM maven:3.9.9-eclipse-temurin-17 AS build
WORKDIR /src
COPY pom.xml .
COPY src ./src
RUN mvn -B -DskipTests package dependency:copy-dependencies -DoutputDirectory=target/dependency
FROM eclipse-temurin:17-jre
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/wsfed-caep-0.1.0.jar /app/wsfed-caep.jar
COPY --from=build /src/target/dependency /app/dependency
COPY demo ./demo
COPY scripts ./scripts
ENV PORT=3000
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s \
  CMD curl -fsS "http://127.0.0.1:${PORT}/healthz" || exit 1
CMD ["java", "-cp", "/app/wsfed-caep.jar:/app/dependency/*", "com.iyasec.wsfed.demo.Demo"]
