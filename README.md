# Auth Service for small business or organization where number of users are few but needs a secured authentication System without any external Database

This project implements a user authentication and authorization system using Spring Boot, Spring Security, JWT (JSON Web Tokens), Refresh Tokens, and a persistent H2 database.

## Features

*   User registration (`/api/auth/signup`)
*   User login (`/api/auth/signin`) with JWT generation
*   JWT validation for protected resources
*   Refresh token mechanism (`/api/auth/refreshtoken`) to obtain new JWTs without re-login
*   Role-based authorization (Roles: `ADMIN`, `APP_GROUP`, `KPC`, `OTHERS`)
*   Persistent H2 database (data stored in `./data/auth_db.mv.db`)
*   Centralized exception handling

## Prerequisites

*   Java Development Kit (JDK) 17 or later
*   Apache Maven 3.6 or later

## Setup and Running

1.  **Clone the repository:**
    ```bash
    git clone <your-repository-url>
    cd auth-experiment
    ```
2.  **Build the project:**
    ```bash
    mvn clean install
    ```
3.  **Run the application:**
    ```bash
    mvn spring-boot:run
    ```
    Alternatively, you can run the packaged JAR:
    ```bash
    java -jar target/auth-experiment-0.0.1-SNAPSHOT.jar
    ```
4.  The application will start on `http://localhost:8080` (or the configured port).

## Configuration

Key configuration properties are located in `src/main/resources/application.properties`:

*   `spring.datasource.url`: H2 database file location.
*   `spring.datasource.username`/`password`: H2 database credentials.
*   `spring.h2.console.enabled=true`: Enables the H2 web console.
*   `spring.h2.console.path=/h2-console`: Path to access the H2 console.
*   `jwt.secret`: **IMPORTANT:** Change this to a strong, unique secret key!
*   `jwt.expiration`: JWT token validity duration (milliseconds).
*   `jwt.refresh.expiration`: Refresh token validity duration (milliseconds).

## H2 Database Console

You can access the H2 database console in your browser (while the application is running) to inspect the data:

*   URL: `http://localhost:8080/h2-console`
*   JDBC URL: `jdbc:h2:file:./data/auth_db` (Make sure this matches the `spring.datasource.url` but without the `mem:` prefix if you used file persistence)
*   Username: `sa` (or as configured)
*   Password: `password` (or as configured)

## API Endpoints

All endpoints are under the `/api/auth` prefix.

### 1. Sign Up

*   **POST** `/api/auth/signup`
*   **Description:** Registers a new user.
*   **Request Body:**
    ```json
    {
        "username": "testuser",
        "email": "test@example.com",
        "password": "password123",
        "role": ["kpc"] // Optional. Can be ["admin", "app_group", "kpc"]. Defaults to ["others"] if omitted or empty.
    }
    ```
*   **Success Response (200 OK):**
    ```json
    {
        "message": "User registered successfully!"
    }
    ```
*   **Error Responses:**
    *   400 Bad Request: If username/email is already taken or validation fails.

### 2. Sign In

*   **POST** `/api/auth/signin`
*   **Description:** Authenticates a user and returns JWT and refresh tokens.
*   **Request Body:**
    ```json
    {
        "username": "testuser",
        "password": "password123"
    }
    ```
*   **Success Response (200 OK):**
    ```json
    {
        "token": "eyJhbGciOiJIUzI1NiJ9...", // Access Token (JWT)
        "type": "Bearer",
        "refreshToken": "uuid-refresh-token-string...",
        "id": 1,
        "username": "testuser",
        "email": "test@example.com",
        "roles": [
            "ROLE_KPC" // Note: Roles are prefixed with ROLE_ internally by Spring Security
        ]
    }
    ```
*   **Error Responses:**
    *   401 Unauthorized: If credentials are invalid.

### 3. Refresh Token

*   **POST** `/api/auth/refreshtoken`
*   **Description:** Obtains a new JWT access token using a valid refresh token.
*   **Request Body:**
    ```json
    {
        "refreshToken": "uuid-refresh-token-string..."
    }
    ```
*   **Success Response (200 OK):**
    ```json
    {
        "accessToken": "eyJhbGciOiJIUzI1NiJ9...new_token...", // New Access Token
        "refreshToken": "uuid-refresh-token-string...", // The original refresh token
        "tokenType": "Bearer"
    }
    ```
*   **Error Responses:**
    *   403 Forbidden: If the refresh token is invalid, expired, or not found.

## Authentication

For accessing protected endpoints (not shown here, but any endpoint *not* under `/api/auth`), include the JWT access token in the `Authorization` header:

```
Authorization: Bearer <your_jwt_access_token>
```
