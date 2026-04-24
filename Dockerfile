# -------- STAGE 1: Build --------
FROM maven:3.9.9-eclipse-temurin-21 AS builder

WORKDIR /app

# Copiar pom y descargar dependencias (cache layer)
COPY pom.xml .
RUN mvn dependency:go-offline

# Copiar el código fuente
COPY src ./src

# Compilar el proyecto
RUN mvn clean package -DskipTests

# -------- STAGE 2: Runtime --------
FROM eclipse-temurin:21-jdk-alpine

WORKDIR /app

# Copiar el jar generado desde el stage anterior
COPY --from=builder /app/target/auth-0.0.1-SNAPSHOT.jar app.jar

# Exponer el puerto
EXPOSE 8080

# Ejecutar la app
ENTRYPOINT ["java","-jar","/app/app.jar"]