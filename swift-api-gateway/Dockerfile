FROM maven:3-eclipse-temurin-21-alpine AS build
WORKDIR /workspace
COPY ./pom.xml ./
RUN mvn dependency:go-offline
COPY . .
RUN mvn package

FROM eclipse-temurin:21-jre-alpine
VOLUME /tmp
RUN apk --no-cache add curl
COPY --from=build /workspace/target/*.jar /app.jar
ENTRYPOINT ["sh", "-c", "java -jar /app.jar"]