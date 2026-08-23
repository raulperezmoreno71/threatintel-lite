# ThreatIntel Lite

![Tests](https://github.com/raulperezmoreno71/threatintel-lite/actions/workflows/tests.yml/badge.svg)

## Overview

ThreatIntel Lite is a REST API built with Spring Boot that analyzes different aspects of a URL and evaluates its HTTP security configuration. The results are grouped into dedicated analysis modules, including DNS resolution, HTTP behavior, SSL/TLS certificate information and HTTP security header assessment.

Analysis results are also persisted in a PostgreSQL database using Spring Data JPA and Hibernate, allowing previous analyses to be stored for future retrieval. The application also includes user account persistence and a registration flow with secure password hashing using Spring Security.

The project is designed to explore how backend applications interact with Internet protocols such as DNS and HTTP while following clean architecture principles and modern Java development practices. 

Rather than only collecting HTTP metadata, ThreatIntel Lite also evaluates the security posture of a target website by inspecting common security headers and providing actionable recommendations.

The API also produces an overall HTTP security header assessment by calculating a weighted score and assigning a security grade based on the analyzed headers.

ThreatIntel Lite is being developed incrementally, with each feature focusing on understanding a specific backend or networking concept rather than simply adding functionality.

## Analysis Workflow

```text
                User Request
                     │
                     ▼
               URL Validation
                     │
                     ▼
             Domain Extraction
                     │
                     ▼
┌──────────────────────────────────────────────┐
│              Analysis Modules                │
├──────────────────────────────────────────────┤
│                                              │
│  DNS Analysis                                │
│      └── Resolve IP addresses                │
│                                              │
│  HTTP Analysis                               │
│      ├── Redirect chain                      │
│      ├── Status code                         │
│      ├── Content-Type                        │
│      ├── Server                              │
│      ├── Content-Length                      │
│      └── Response time                       │
│                                              │
│  SSL/TLS Analysis                            │
│      ├── Issuer                              │
│      ├── Subject                             │
│      ├── Validity period                     │
│      ├── Days until expiration               │
│      ├── Certificate status                  │
│      └── Renewal recommendation              │
│                                              │
│  Security Headers Assessment                 │
│      ├── Strict-Transport-Security           │
│      ├── Content-Security-Policy             │
│      ├── X-Frame-Options                     │
│      ├── X-Content-Type-Options              │
│      ├── Referrer-Policy                     │
│      └── Permissions-Policy                  │
│                                              │
│  Security Assessment                         │
│      ├── Security score                      │
│      ├── Security grade                      │
│      └── Header summary                      │
│                                              │
└──────────────────────────────────────────────┘
                     │
                     ▼
               Analysis Results
                     │
          ┌──────────┴──────────┐
          │                     │
          ▼                     ▼
   JPA Entity Mapping     Structured JSON
          │                  Response
          ▼
   Spring Data JPA
          │
          ▼
      Hibernate
          │
          ▼
      PostgreSQL
```

ThreatIntel Lite processes each URL through independent analysis modules and combines their results into a single structured JSON response.

## Features

 - [x] Validate HTTP and HTTPS URLs.
 - [x] Extract the domain from a URL.
 - [x] Resolve all available IP addresses through DNS.
 - [x] Retrieve the HTTP status code.
 - [x] Detect the response Content-Type.
 - [x] Identify the responding web server.
 - [x] Retrieve the declared Content-Length header.
 - [x] Measure the total HTTP response time.
 - [x] Handle invalid requests through global exception handling.
 - [x] Analyze SSL/TLS certificates.
 - [x] Retrieve certificate issuer and subject.
 - [x] Retrieve certificate validity dates.
 - [x] Calculate remaining days until certificate expiration.
 - [x] Analyze and evaluate common HTTP security headers.
 - [x] Classify each security header as GOOD, WARNING or MISSING.
 - [x] Provide security recommendations for each analyzed header.
 - [x] Calculate an overall website security score.
 - [x] Assign an overall security grade (A-F).
 - [x] Return structured JSON responses grouped by analysis module.
 - [x] Follow HTTP redirect chains manually.
 - [x] Measure response time for each redirect.
 - [x] Identify the final destination URL.
 - [x] Classify SSL certificates as GOOD, WARNING or CRITICAL.
 - [x] Follow a clean layered architecture (Controller, Service, DTO and Exception Handler).
 - [x] Interactive API documentation with swagger UI.
 - [x] OpenAPI 3 specification generation.
 - [x] Persist complete URL analysis results using PostgreSQL.
 - [x] Map analysis data to relational entities using Spring Data JPA and Hibernate.
 - [x] Model one-to-one and one-to-many relationships between analysis modules.
 - [x] Retrieve persisted analyses by ID.
 - [x] Retrieve all persisted analyses.
 - [x] Delete persisted analyses by ID.
 - [x] Map persisted JPA entities to structured API responses.
 - [x] Persist user accounts using PostgreSQL.
 - [x] Associate persisted analyses with users.
 - [x] Register new users through a dedicated REST endpoint.
 - [x] Hash user passwords using Spring Security PasswordEncoder.
 - [x] Prevent duplicate user registration by email.
 - [x] Return structured 409 Conflict responses for duplicate emails.
 - [x] Authenticate users with email and password.
 - [x] Generate JWT access tokens after successful login.
 - [x] Configure JWT expiration and signing secret through application configuration.

## Tech Stack

 - **Language:** Java 21
 - **Framework:** Spring Boot
 - **Security:** Spring Security, Password Encoder, JWT
 - **Persistence:** Spring Data JPA, Hibernate
 - **Database:** PostgreSQL
 - **Build Tool:** Maven
 - **Networking:** Java HttpClient, JSSE (SSL/TLS)
 - **JSON Serialization:** Jackson
 - **Version Control:** Git
 - **Repository Hosting:** GitHub
 - **API Documentation:** SpringDoc OpenAPI (Swagger UI)
 - **Testing:** JUnit 5, Mockito, Spring MockMvc, TestContainers
 - **Containerization:** Docker
 - **CI:** GitHub Actions

## Project Structure

```text
backend
├── .mvn
├── pom.xml
├── mvnw
├── mvnw.cmd
├── request.http
└── src
    └── main
        └── java
            └── io.github.raulperezmoreno71.threatintel
                ├── config
                ├── controller
                ├── dto
                ├── entity
                ├── exception
                ├── model
                ├── repository
                ├── security
                └── service
```

### `controller`

Receives incoming HTTP requests, delegates the processing to the service layer and returns the API response.

### `service`

Contains the application's business logic and coordinates URL validation, analysis modules, persistence and user account operations.

### `dto`

Defines the request and response objects exchanged between the API and its clients, including URL analysis, persistence and user registration DTOs.

### `model`

Contains internal domain models representing the results of each analysis module, including DNS, HTTP, redirect chains, SSL/TLS and security header assessments.

### `exception`

Provides centralized exception handling and returns consistent error responses.

The project follows a layered architecture, keeping responsibilities separated to improve readability, maintainability and scalability.

### `entity`

Defines the JPA entities used to persist analysis results, user accounts and their relationships in PostgreSQL.

### `repository`

Provides database access through Spring Data JPA repositories.

## Persistence

ThreatIntel Lite persists completed analyses in PostgreSQL using Spring Data JPA and Hibernate.

The persistence model includes:

- General analysis information
- DNS analysis and resolved IP addresses
- HTTP analysis and redirect chain
- SSL/TLS certificate analysis
- Security header analysis
- Overall security assessment

Relationships between entities are modeled using JPA associations such as `@OneToOne`, `@OneToMany` and `@ManyToOne`.

## API example

### Analyze a URL

**Request**

```http
POST /api/analyze
Content-Type: application/json

{
    "url": "https://github.com"
}
```

**Successful Response**

> Each security header includes its detected value, a security assessment and an actionable recommendation when applicable. The API also calculates an overall security score and grade based on the analyzed headers.
> 
> The Content Security Policy value has been shortened for readability.

```json
{
  "message": "URL analyzed successfully",
  "url": "https://github.com/",
  "domain": "github.com",
  "dns": {
    "ips": [
      "140.82.121.3"
    ]
  },
  "http": {
    "statusCode": 200,
    "contentType": "text/html; charset=utf-8",
    "server": "github.com",
    "contentLength": null,
    "finalUrl": "https://github.com/",
    "totalResponseTimeMs": 640,
    "redirectChain": [
      {
        "url": "https://github.com/",
        "statusCode": 200,
        "location": null,
        "responseTimeMs": 640
      }
    ]
  },
  "ssl": {
    "issuer": "CN=Sectigo Public Server Authentication CA DV E36,O=Sectigo Limited,C=GB",
    "subject": "CN=github.com",
    "validFrom": "2026-07-03",
    "validUntil": "2026-09-30",
    "daysUntilExpiration": 68,
    "status": "GOOD",
    "recommendation": null
  },
  "securityHeaders": {
    "strictTransportSecurity": {
      "present": true,
      "value": "max-age=31536000; includeSubdomains; preload",
      "status": "GOOD",
      "recommendation": null
    },
    "contentSecurityPolicy": {
      "present": true,
      "value": "default-src 'none'; ... gist.github.com/assets-cdn/worker/",
      "status": "WARNING",
      "recommendation": "Avoid using 'unsafe-inline'. Use nonces or hashes for required inline scripts and styles."
    },
    "xFrameOptions": {
      "present": true,
      "value": "deny",
      "status": "GOOD",
      "recommendation": null
    },
    "xContentTypeOptions": {
      "present": true,
      "value": "nosniff",
      "status": "GOOD",
      "recommendation": null
    },
    "referrerPolicy": {
      "present": true,
      "value": "origin-when-cross-origin, strict-origin-when-cross-origin",
      "status": "GOOD",
      "recommendation": null
    },
    "permissionsPolicy": {
      "present": false,
      "value": null,
      "status": "MISSING",
      "recommendation": "Add a Permissions-Policy header to restrict access to unnecessary browser features."
    }
  },
  "securityAssessment": {
    "score": 75,
    "grade": "C",
    "goodHeaders": 4,
    "warningHeaders": 1,
    "missingHeaders": 1
  }
}
```

### Security Grade Scale

| Grade | Score |
|------:|------:|
| A | 90–100 |
| B | 80–89 |
| C | 70–79 |
| D | 60–69 |
| F | 0–59 |

**Validation Error**

```json
{
    "status": 400,
    "error": "Bad Request",
    "message": "URL cannot be null or blank",
    "path": "/api/analyze"
}
```

## Analysis History API

Retrieve all stored analyses:

```http
GET /api/analyses
```

Retrieve a stored analysis by ID:

```http
GET /api/analyses/{id}
```

Delete a stored analysis:

```http
DELETE /api/analyses/{id}
```

## Authentication API

### Register

Register new user:

```http request
POST /api/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "StrongPassword123!"
}
```

**Successful Response**
```json
{
  "id": 1,
  "email": "user@example.com",
  "status": "ACTIVE",
  "createdAt": "2026-08-20T12:45:30"
}
```

**Attempting to register an already existing email returns**
```json
{
  "status": 409,
  "error": "Conflict",
  "message": "Email is already registered",
  "path": "/api/auth/register"
}
```

### Login

```http request
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "StrongPassword123"
}
```

**Successful response**
```json
{
  "id": 1,
  "email": "user@example.com",
  "status": "ACTIVE",
  "message": "Login successful",
  "token": "eyJhbGciOiJIUzI1NiJ9..."
}
```

## Getting Started

### Prerequisites

Before running the project, make sure you have installed:

 - Java 21
 - PostgreSQL
 - Git
 - Docker Desktop (required for Testcontainers integration tests)

### Clone the repository

```bash
git clone https://github.com/raulperezmoreno71/threatintel-lite.git
cd threatintel-lite/backend
```

### Database setup

Create a PostgreSQL database named:

```text
threatintel
```

Configure the following environment variables:

```text
DB_URL=jdbc:postgresql://localhost:5432/threatintel
DB_USERNAME=postgres
DB_PASSWORD=your_postgresql_password
```

### Run the application

Run these commands from the `backend` directory.

Linux / macOS:

```bash
./mvnw spring-boot:run
```

Windows:

```bash
.\mvnw.cmd spring-boot:run
```

By default, the application will start on:

```text
http://localhost:8080
```

### OpenAPI Documentation

Once the application is running, the interactive API documentation is available at:

```text
http://localhost:8080/swagger-ui/index.html
```

### Test the API

Send a POST request to:

```text
http://localhost:8080/api/analyze
```

using the following JSON body:

```json
{
    "url": "https://google.com"
}
```

## Testing

The project includes automated tests covering the analysis logic, service layer, web layer and persistence layer.

The test suite includes:

- Unit tests for URL validation, DNS resolution, HTTP analysis, SSL/TLS analysis, security header evaluation and security score calculation.
- Mock-based service tests using Mockito to isolate repositories and external dependencies.
- Web layer tests using Spring MockMvc to verify analysis and history endpoints, including error responses.
- Persistence integration tests using Testcontainers with a real PostgreSQL instance running in Docker.
- JPA relationship and cascade tests covering DNS analysis, HTTP redirect chains, SSL/TLS data, security headers and security assessment persistence.
- Cascade deletion tests verifying that related persisted entities are removed together with their parent analysis.
- Unit and web layer tests for user registration, including successful registration and duplicate email handling.

Run the complete test suite from the `backend` directory using the Maven Wrapper:

```bash
./mvnw test
```

On windows:

```bash
.\mvnw.cmd test
```

The complete test suite is also executed automatically by GitHub Actions on every push and pull request, including PostgreSQL integration tests powered by Testcontainers.

## Roadmap

The project is being developed incrementally, with each milestone focused on learning and implementing a specific backend or networking concept.

### Completed
 - [x] URL validation
 - [x] DNS resolution
 - [x] HTTP status code analysis
 - [x] HTTP redirection detection
 - [x] HTTP response header analysis
 - [x] HTTP security header assessment
 - [x] HTTP response time measurement
 - [x] Global exception handling
 - [x] SSL/TLS certificate status evaluation
 - [x] Modular JSON response structure
 - [x] Redirect chain analysis
 - [x] Security header assessment and recommendations
 - [x] Overall security score calculation
 - [x] Overall security grade assignment
 - [x] REST API documentation (OpenAPI / Swagger)
 - [x] Unit tests for analysis components
 - [x] Service layer tests with Mockito
 - [x] Web layer tests with Spring MockMvc
 - [x] PostgreSQL integration tests with Testcontainers
 - [x] JPA relationship and cascade persistence tests
 - [x] Cascade deletion integration tests 
 - [x] Domain-specific exception handling
 - [x] PostgreSQL persistence
 - [x] JPA/Hibernate entity mapping
 - [x] Persistent storage of complete analysis results
 - [x] GitHub Actions continuous integration
 - [x] Retrieve stored analysis by ID.
 - [x] Analysis history retrieval.
 - [x] Analysis history deletion.
 - [x] User persistence and analysis ownership.
 - [x] User registration.
 - [x] Secure password hashing with Spring Security.
 - [x] Duplicate email handling.
 - [x] Automated user registration tests.
 - [x] User login and credential validation.
 - [x] JWT generation and validation.

### Planned

 - [ ] Configurable security scoring policy
 - [ ] Dockerized application deployment
 - [ ] JWT authentication filter and protected API endpoints.
 - [ ] Domain reputation analysis using external services

## Author

**Raúl Pérez Moreno**

Computer Engineering student at the University of Málaga (UMA), currently developing backend projects with Java and Spring Boot, focusing on networking, REST APIs and software architecture.

 - GitHub: https://github.com/raulperezmoreno71/
 - LinkedIn: https://www.linkedin.com/in/ra%C3%BAl-p%C3%A9rez-moreno-ba0aab3a7/
