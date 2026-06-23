# Testing — BEsifaAuthService

## 1. Estrategia de Testing

El proyecto sigue una estrategia de pruebas en pirámide clásica:

- **Pruebas Unitarias** (JUnit 5 + Mockito): Cubren servicios, utilidades, validación de DTOs y lógica JWT.
- **Pruebas de Controladores** (MockMvc): Validan que los endpoints respondan correctamente en términos de HTTP status, estructura JSON y autorización.
- **Pruebas de Repositorios** (@DataJpaTest con H2): Verifican consultas JPA personalizadas.
- **Pruebas de Seguridad** (MockMvc + Security): Validan filtros JWT, RBAC y CORS.

## 2. Stack

| Herramienta | Versión | Propósito |
|---|---|---|
| JUnit 5 | 5.11+ | Framework de testing |
| Mockito | 5.x | Mocking de dependencias |
| MockMvc | Spring | Tests de controladores |
| H2 Database | 2.x | Base de datos en memoria para tests de repositorio |
| JaCoCo | 0.8.12 | Cobertura de código |
| Spring Security Test | 6.x | Testing de seguridad |

## 3. Estructura de Tests

```
src/test/java/com/evecta/auth/
├── AuthApplicationTests.java          # Test de contexto
├── util/
│   └── TestDataBuilder.java           # Factoría de datos de prueba
├── dto/
│   ├── RutValidatorTest.java
│   ├── UserCreateDTOValidationTest.java
│   ├── LoginRequestDTOValidationTest.java
│   └── ChangePasswordRequestDTOValidationTest.java
├── service/
│   ├── AuthServiceTest.java
│   ├── UserServiceTest.java
│   ├── TokenServiceTest.java
│   ├── JwtServiceTest.java
│   ├── AuditoriaServiceTest.java
│   └── EmailServiceTest.java
├── controller/
│   ├── AuthControllerTest.java
│   ├── UserControllerTest.java
│   └── TokenControllerTest.java
├── repository/
│   ├── IUserRepositoryTest.java
│   └── ITokenRepositoryTest.java
├── security/
│   ├── JwtAuthenticationFilterTest.java
│   └── SecurityConfigTest.java
└── exception/
    └── GlobalExceptionHandlerTest.java
```

## 4. Convenciones

- **Naming**: `{metodo}_dado[condicion]_[resultado]()` en snake_case.
  - Ejemplo: `login_conCredencialesInvalidas_retorna401()`
- **Aislamiento**: 
  - Servicios: `@ExtendWith(MockitoExtension.class)`, repositorios/clients mockeados.
  - Controladores: `@WebMvcTest(Controller.class)`, servicios mockeados.
  - Repositorios: `@DataJpaTest` con H2.
- **Assertions**: Preferir AssertJ fluido sobre assertions de JUnit.
- **Sin `@SpringBootTest`**: Solo se usa en `AuthApplicationTests`. Todos los demás tests usan slices.

## 5. Cobertura (JaCoCo)

- Mínimo: **75%** de cobertura de instrucciones en `com.evecta.auth`.
- Excluidos del reporte:
  - `AuthApplication.class` (entry point)
  - `config/OpenApiConfig.class`, `config/DataInitializer.class`
  - `dto/**/*.class` (data classes sin lógica)
  - `model/**/*.class` (entidades y enums)
  - `client/**/*.class` (Feign client interface)
- Umbral configurado en `pom.xml` y verificado en `mvn verify`.

## 6. Mapeo con Plan de Pruebas SIFA

| CP | Descripción | Test(s) |
|---|---|---|
| CP-001 | Login exitoso | AuthServiceTest.login_conCredencialesValidas_retornaTokens(), AuthControllerTest.login_conDatosValidos_retorna200(), JwtServiceTest.generateToken_retornaJwtValido() |
| CP-002 | Login credenciales inválidas | AuthServiceTest.login_conPasswordIncorrecto_lanzaExcepcion(), AuthControllerTest.login_conPasswordIncorrecto_retorna401() |
| CP-003 | Login USER_APP desde web bloqueado | AuthServiceTest.login_userAppDesdeWeb_lanzaExcepcion() |
| CP-023 | Crear usuario ADMIN | UserServiceTest.createUser_datosValidos_retornaUsuario(), UserControllerTest.registerUser_conAdmin_retorna201() |
| CP-024 | Crear usuario sin token ADMIN | UserControllerTest.registerUser_sinPermisos_retorna403() |
| CP-039 | Registro de auditoría | AuditoriaServiceTest.registrarAccion_enviaACoreService() |
| CP-054 | Token JWT expirado | JwtServiceTest.isTokenValid_tokenExpirado_retornaFalse(), JwtAuthenticationFilterTest.tokenExpirado_retorna401() |
| CP-055 | Refresh token rotation | AuthServiceTest.refresh_conTokenValido_emiteNuevosTokens(), AuthServiceTest.refresh_conTokenRevocado_lanzaExcepcion() |
| CP-057 | Validación de RUT | RutValidatorTest.validarRut_rutInvalido_retornaFalse(), UserCreateDTOValidationTest.rutInvalido_errorValidacion(), UserServiceTest.createUser_rutInvalido_lanzaExcepcion() |
| CP-060 | Error 500 manejado global | GlobalExceptionHandlerTest.illegalArgument_retorna400json(), GlobalExceptionHandlerTest.badCredentials_retorna401() |

## 7. Ejecución

```bash
# Ejecutar todos los tests
./mvnw test

# Ejecutar tests con verificación de cobertura
./mvnw verify

# Ejecutar una clase específica
./mvnw test -Dtest=AuthServiceTest

# Reporte JaCoCo (después de verify)
# Abrir target/site/jacoco/index.html en el navegador

# Excluir verificaciones JaCoCo (si es necesario)
./mvnw test -Djacoco.skip=true
```

## 8. Buenas prácticas

1. **AAA Pattern**: Arrange-Act-Assert en cada test.
2. **Mock solo lo necesario**: No mockear tipos de valor ni objetos simples.
3. **Tests deterministas**: Sin fechas fijas, usar Clock mockeable o fechas relativas.
4. **Un concepto por test**: Un test verifica un solo comportamiento.
5. **No depender del orden**: Cada test es independiente y autocontenido.
6. **Nombrar los mocks**: Usar `@Mock` con nombres descriptivos o Mockito.withSettings().name().
7. **Cobertura de bordes**: Probar casos límite, no solo el camino feliz.
8. **Mantener los tests rápidos**: < 100ms por test unitario, < 1s por test de controlador.
