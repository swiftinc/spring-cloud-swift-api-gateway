FROM maven:3-eclipse-temurin-21-alpine AS build
WORKDIR /workspace
COPY --chown=1001:0 ./pom.xml ./
RUN mvn dependency:go-offline
COPY --chown=1001:0 . .
RUN mvn package

FROM eclipse-temurin:21-jre-alpine
VOLUME /tmp
RUN apk --no-cache add curl
COPY --from=build /workspace/target/*.jar /app.jar
ENTRYPOINT ["sh", "-c", "java -jar /app.jar"]