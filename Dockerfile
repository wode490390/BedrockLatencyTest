FROM bellsoft/liberica-openjdk-alpine-musl:8 AS build

WORKDIR /build

COPY .mvn/ .mvn
COPY mvnw pom.xml ./

RUN ./mvnw -B dependency:resolve

COPY src ./src

RUN ./mvnw -B clean package

FROM bellsoft/liberica-openjre-alpine-musl:17 AS run

WORKDIR /app

COPY --from=build /build/target/latency-proxy-1.0.0-SNAPSHOT.jar ./proxy.jar

EXPOSE 19121/udp

ENTRYPOINT ["java"]
CMD ["-jar", "/app/proxy.jar"]
