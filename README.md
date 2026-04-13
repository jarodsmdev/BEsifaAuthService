# Auth API (Spring Boot)

Proyecto de autenticación construido con Spring Boot.

Esta aplicación está asociada a **MySQL** y su configuración principal se realiza mediante variables de entorno.

## Tecnologías

- Java 21
- Spring Boot 3
- Spring Security
- Spring Data JPA
- Maven
- MySQL

## Requisitos

- Java 21 instalado
- Maven 3.9+ (o usar `./mvnw`)
- MySQL 8+ en ejecución

## Variables de entorno

Debes definir las siguientes variables antes de ejecutar la aplicación:

| Variable | Requerida | Descripción | Ejemplo |
|---|---|---|---|
| `DB_HOST` | Sí | Host de MySQL | `localhost` |
| `DB_PORT` | Sí | Puerto de MySQL | `3306` |
| `DB_NAME` | Sí | Nombre de la base de datos | `auth_db` |
| `DB_USER` | Sí | Usuario de MySQL | `root` |
| `DB_PASSWORD` | Sí | Contraseña de MySQL | `root123` |
| `BCRYPT_STRENGTH` | Sí | Fuerza de encriptación BCrypt (recomendado 10-12) | `10` |
| `SERVER_PORT` | No | Puerto de la API (por defecto 8080) | `8080` |

## Configuración de base de datos

La aplicación usa esta URL JDBC (definida en `application.properties`):

```properties
spring.datasource.url=jdbc:mysql://${DB_HOST}:${DB_PORT}/${DB_NAME}?useSSL=false&serverTimezone=America/Santiago&allowPublicKeyRetrieval=true&createDatabaseIfNotExist=true
```

Notas importantes:

- `createDatabaseIfNotExist=true` permite crear la base de datos si no existe.
- `spring.jpa.hibernate.ddl-auto=update` actualiza el esquema automáticamente.

## Cómo ejecutar

### 1. Cargar variables de entorno en VS Code

En la raiz del proyecto asegúrate de tener la carpeta `.vscode` con el archivo `launch.json` configurado para cargar las variables de entorno. Ejemplo:

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "type": "java",
      "name": "Spring Boot-App",
      "request": "launch",
      "mainClass": "com.evecta.auth.AuthApplication",
      "envFile": "${workspaceFolder}/.env"
    }
  ]
}
```

Además, debes existir un archivo `.env` en la raíz del proyecto con las variables definidas, se provee un ejemplo `.env.example` que puedes copiar y renombrar a `.env`

### 2. Levantar la aplicación

Con VS Code:

Puedes usar la combinación de teclas `Ctrl+Shift+D` para abrir la vista de depuración y luego iniciar la configuración "Spring Boot-App".

Si usas otro IDE o terminal, asegúrate de cargar las variables de entorno antes de ejecutar.

Con Maven Wrapper (recomendado):

```bash
./mvnw spring-boot:run
```

O con Maven instalado:

```bash
mvn spring-boot:run
```

La API quedará disponible en:

```bash
http://localhost:8080
```

Si defines otro `SERVER_PORT`, cambia el puerto en la URL.

## Ejecutar pruebas

```bash
./mvnw test
```

## Logs

Los logs se generan en:

- `logs/auth-app.log`

## Solución rápida de problemas

- Error de conexión a MySQL: revisa `DB_HOST`, `DB_PORT`, `DB_USER` y `DB_PASSWORD`.
- Puerto ocupado: cambia `SERVER_PORT`.
- Error de credenciales: valida usuario/contraseña y permisos en MySQL.
