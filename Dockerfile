FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /workspace
COPY Packet_analyzer-main/java-port/pom.xml Packet_analyzer-main/java-port/pom.xml
RUN mvn -q -f Packet_analyzer-main/java-port/pom.xml dependency:go-offline
COPY Packet_analyzer-main/java-port/src Packet_analyzer-main/java-port/src
RUN mvn -q -f Packet_analyzer-main/java-port/pom.xml package

FROM eclipse-temurin:25-jre
WORKDIR /app
COPY --from=build /workspace/Packet_analyzer-main/java-port/target/packet-analyzer-java-1.0.0.jar /app/app.jar
EXPOSE 9400
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
