# ThreatIntel Lite

[![Backend tests](https://github.com/raulperezmoreno71/threatintel-lite/actions/workflows/tests.yml/badge.svg)](https://github.com/raulperezmoreno71/threatintel-lite/actions/workflows/tests.yml)

ThreatIntel Lite is a full-stack web application that analyzes the technical security posture of a URL and presents the result as a structured, readable report.

The application combines a Java 21 and Spring Boot REST API with a React and TypeScript client. Authenticated users can run URL analyses, inspect DNS, HTTP, redirect, TLS and security-header information, calculate an overall score, and save selected reports to a private history backed by PostgreSQL.

> [!IMPORTANT]
> ThreatIntel Lite provides a lightweight technical assessment based on publicly observable URL, certificate and HTTP-header information. It is not a vulnerability scanner, penetration-testing tool or substitute for a professional security audit.

## Version 1 overview

The first consolidated version includes the complete user journey:

1. Create an account and sign in.
2. Submit an HTTP or HTTPS URL.
3. Run the DNS, HTTP, redirect, TLS and security-header analysis.
4. Review the score, grade and recommendations in the web interface.
5. Save selected results to a user-owned history.
6. Reopen stored analyses from the private history.
7. Change the account password and close the session.

Authentication is handled with a signed JWT stored in an HttpOnly cookie. Protected backend resources are scoped to the authenticated user, so saved analyses cannot be retrieved or deleted through another account.

## Main features

### URL intelligence

- HTTP and HTTPS URL validation.
- Domain extraction and DNS resolution.
- Collection of all resolved IP addresses.
- Manual redirect tracking for `301`, `302`, `303`, `307` and `308` responses.
- Relative redirect resolution and a maximum redirect limit.
- Final HTTP status, URL, content type, server and declared content length.
- Response time for each request and for the complete redirect chain.

### TLS certificate analysis

- Certificate issuer and subject.
- Validity start and end dates.
- Remaining days until expiration.
- `GOOD`, `WARNING` or `CRITICAL` classification.
- Renewal recommendation when the certificate is close to expiration or expired.
- Explicit timeout, handshake and general TLS error handling.

TLS analysis is omitted for plain HTTP destinations.

### HTTP security assessment

ThreatIntel Lite evaluates six response headers:

- `Strict-Transport-Security`
- `Content-Security-Policy`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`

Every header receives a status, its detected value and an actionable recommendation when improvement is needed. The results are combined into a weighted score and an overall grade.

| Grade | Score |
|:-----:|------:|
| A | 90–100 |
| B | 80–89 |
| C | 70–79 |
| D | 60–69 |
| F | 0–59 |

### Accounts and private history

- User registration with unique email addresses.
- Password hashing through Spring Security's `PasswordEncoder`.
- Credential-based login.
- JWT authentication through an HttpOnly `access_token` cookie.
- Current-user endpoint and protected application routes.
- Password changes after verifying the current password.
- Explicit logout through cookie invalidation.
- Complete analysis persistence in PostgreSQL.
- Per-user listing, detail and deletion of stored reports.

### Web experience

- Responsive public landing page.
- Registration and login forms.
- Authenticated analysis dashboard.
- Detailed presentation of every analysis module.
- Save/discard workflow for newly generated reports.
- Private analysis history and report detail views.
- Loading, empty, success and error states.
- Semantic HTML, keyboard focus styles and accessible status messages.
- Reduced-motion support for users who request it.

## Architecture

The repository contains two independent applications:

```text
threatintel-lite/
├── backend/     Java 21 + Spring Boot REST API
├── frontend/    React + TypeScript + Vite client
├── .github/     Continuous integration workflows
└── README.md
```

### Request flow

```text
React client
    │
    │ JSON over HTTP + HttpOnly authentication cookie
    ▼
Spring Security / JWT filter
    │
    ▼
REST controllers
    │
    ├── Account service ───────────────► User repository
    │
    ├── Analysis coordinator
    │       ├── URL validation
    │       ├── DNS analysis
    │       ├── HTTP and redirects
    │       ├── TLS certificate analysis
    │       └── Security-header scoring
    │
    └── Analysis history service ─────► Analysis repository
                                            │
                                            ▼
                                       PostgreSQL
```

The analysis operation and persistence are intentionally separate in v1. A report is generated first and is only persisted when the user chooses **Save analysis**.

### Backend packages

```text
backend/src/main/java/io/github/raulperezmoreno71/threatintel/
├── config/       Security, CORS and OpenAPI configuration
├── controller/   REST endpoints
├── dto/          API request and response contracts
├── entity/       JPA persistence model
├── exception/    Domain exceptions and global error handling
├── model/        Analysis result models and status types
├── repository/   Spring Data JPA repositories
├── security/     JWT request filter and authentication entry point
└── service/      Use cases and analysis modules
```

The backend follows a conventional layered design. Controllers handle HTTP concerns, services coordinate application behaviour, repositories isolate database access, and the analysis modules each focus on one technical responsibility.

### Frontend structure

```text
frontend/src/
├── api/          HTTP access to authentication and analysis endpoints
├── components/   Reusable landing-page and report components
├── pages/        Public and authenticated route-level views
├── App.tsx       Application routes
├── main.tsx      React entry point
└── types.ts      Shared API response types
```

The frontend is a client-rendered single-page application. React Router manages navigation and the browser sends the authentication cookie using `credentials: "include"`.

## Technology stack

| Area | Technology |
|---|---|
| Backend language | Java 21 |
| Backend framework | Spring Boot 4 |
| Web and security | Spring MVC, Spring Security, JWT |
| Persistence | Spring Data JPA, Hibernate |
| Database | PostgreSQL |
| Networking | Java `HttpClient`, DNS APIs and JSSE |
| API documentation | SpringDoc OpenAPI / Swagger UI |
| Frontend | React 19, TypeScript 6, React Router 7 |
| Build tooling | Maven Wrapper, Vite 8, npm |
| Backend testing | JUnit 5, Mockito, MockMvc, Testcontainers |
| Continuous integration | GitHub Actions |

## API

The local API base URL is:

```text
http://localhost:8080
```

### Endpoint summary

| Method | Endpoint | Authentication | Description |
|---|---|:---:|---|
| `POST` | `/api/auth/register` | No | Register a user |
| `POST` | `/api/auth/login` | No | Authenticate and set the JWT cookie |
| `POST` | `/api/auth/logout` | No | Expire the authentication cookie |
| `GET` | `/api/auth/me` | Yes | Return the authenticated user |
| `POST` | `/api/auth/change-password` | Yes | Change the current user's password |
| `POST` | `/api/analyze` | Yes | Analyze a URL |
| `GET` | `/api/analyses` | Yes | List the user's saved analyses |
| `POST` | `/api/analyses` | Yes | Save a completed analysis |
| `GET` | `/api/analyses/{id}` | Yes | Retrieve one owned analysis |
| `DELETE` | `/api/analyses/{id}` | Yes | Delete one owned analysis |
| `GET` | `/api/health` | No | Return the application health response |

All protected requests use the `access_token` cookie created during login. The token is not returned in the response body.

### Authentication example

Register an account:

```http
POST /api/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "StrongPassword123!"
}
```

Successful response:

```json
{
  "id": 1,
  "email": "user@example.com",
  "status": "ACTIVE",
  "createdAt": "2026-08-20T12:45:30"
}
```

Sign in:

```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "StrongPassword123!"
}
```

The response includes the account summary and a `Set-Cookie` header containing the signed JWT:

```json
{
  "id": 1,
  "email": "user@example.com",
  "status": "ACTIVE",
  "message": "Login successful"
}
```

### URL analysis example

```http
POST /api/analyze
Content-Type: application/json
Cookie: access_token=<jwt>

{
  "url": "https://example.com"
}
```

The response is grouped by analysis module:

```json
{
  "message": "URL analyzed successfully",
  "url": "https://example.com",
  "domain": "example.com",
  "dns": {
    "ips": ["93.184.216.34"]
  },
  "http": {
    "statusCode": 200,
    "contentType": "text/html; charset=UTF-8",
    "server": null,
    "contentLength": null,
    "finalUrl": "https://example.com",
    "totalResponseTimeMs": 180,
    "redirectChain": [
      {
        "url": "https://example.com",
        "statusCode": 200,
        "location": null,
        "responseTimeMs": 180
      }
    ]
  },
  "ssl": {
    "issuer": "CN=Example Certificate Authority",
    "subject": "CN=example.com",
    "validFrom": "2026-01-01",
    "validUntil": "2027-01-01",
    "daysUntilExpiration": 108,
    "status": "GOOD",
    "recommendation": null
  },
  "securityHeaders": {
    "strictTransportSecurity": {
      "present": true,
      "value": "max-age=31536000",
      "status": "GOOD",
      "recommendation": null
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

The example is abbreviated: a real response contains the result of all six security-header checks.

### Error contract

Errors use a consistent JSON structure:

```json
{
  "status": 400,
  "error": "Bad Request",
  "message": "URL cannot be null or blank",
  "path": "/api/analyze"
}
```

Common responses include `400 Bad Request`, `401 Unauthorized`, `404 Not Found`, `409 Conflict` and `500 Internal Server Error`.

### OpenAPI documentation

With the backend running, Swagger UI is available at:

```text
http://localhost:8080/swagger-ui/index.html
```

The generated OpenAPI document is available at:

```text
http://localhost:8080/v3/api-docs
```

In the current v1 security configuration, these documentation routes are protected and require a valid authentication cookie.

## Getting started

### Prerequisites

- Git
- Java 21
- A current Node.js LTS release and npm
- PostgreSQL
- Docker Desktop or another compatible Docker environment for integration tests

### 1. Clone the repository

```bash
git clone https://github.com/raulperezmoreno71/threatintel-lite.git
cd threatintel-lite
```

### 2. Create the database

Create a PostgreSQL database for local development:

```sql
CREATE DATABASE threatintel;
```

### 3. Configure the backend

The backend reads its connection and JWT settings from environment variables:

| Variable | Required | Example |
|---|:---:|---|
| `DB_URL` | Yes | `jdbc:postgresql://localhost:5432/threatintel` |
| `DB_USERNAME` | No | `postgres` |
| `DB_PASSWORD` | Yes | `local_password` |
| `JWT_SECRET` | Yes | Base64-encoded HMAC secret |

Example for Linux or macOS:

```bash
export DB_URL='jdbc:postgresql://localhost:5432/threatintel'
export DB_USERNAME='postgres'
export DB_PASSWORD='local_password'
export JWT_SECRET='replace_with_a_base64_encoded_secret'
```

Example for PowerShell:

```powershell
$env:DB_URL = 'jdbc:postgresql://localhost:5432/threatintel'
$env:DB_USERNAME = 'postgres'
$env:DB_PASSWORD = 'local_password'
$env:JWT_SECRET = 'replace_with_a_base64_encoded_secret'
```

Use a Base64-encoded secret with sufficient entropy for the configured HMAC algorithm. Never commit real credentials or production secrets.

### 4. Run the backend

Linux or macOS:

```bash
cd backend
./mvnw spring-boot:run
```

Windows PowerShell:

```powershell
cd backend
.\mvnw.cmd spring-boot:run
```

The API starts at `http://localhost:8080`.

### 5. Run the frontend

From a second terminal:

```bash
cd frontend
npm install
npm run dev
```

The Vite development server starts at `http://localhost:5173`. The v1 frontend expects the backend at `http://localhost:8080`, and the backend CORS configuration allows the local Vite origin.

## Testing and quality checks

### Backend

The backend has 195 automated tests covering:

- URL, DNS, HTTP, redirect, TLS and security-header analysis.
- Weighted security-score calculation.
- User registration, login, current-user lookup and password changes.
- Analysis orchestration and persistence mapping.
- Controller success and error responses with MockMvc.
- JWT creation, expiration and authentication filtering.
- Security configuration, CORS and the authentication entry point.
- Global exception-to-response mapping.
- Repository ownership, relationships, constraints and cascade behaviour.
- Full Spring context startup.
- PostgreSQL persistence through Testcontainers.

Docker must be running because the repository and application-context tests start real PostgreSQL containers.

Linux or macOS:

```bash
cd backend
./mvnw test
```

Windows PowerShell:

```powershell
cd backend
.\mvnw.cmd test
```

### Frontend

Run the static checks and production build from `frontend`:

```bash
npm run lint
npm run build
```

The current GitHub Actions workflow runs the complete backend suite on every push and pull request.

## Current v1 boundaries

Version 1 is feature-complete for its intended learning and portfolio scope, but it should be hardened before exposure as a public production service:

- URL analysis does not yet block private, loopback or link-local destinations. Deployments must restrict access until SSRF protection is added.
- HTTP connection, response-size and total-analysis limits require further hardening.
- Analysis persistence currently accepts the completed report returned by the client.
- Cookie security and CORS values are configured for local development.
- Database schema changes currently rely on Hibernate rather than versioned migrations.
- Saved-analysis listings are not paginated.
- The frontend API origin is currently configured for the local backend.
- Automated frontend tests and end-to-end browser tests are planned for a later iteration.

These constraints are documented explicitly so that the current guarantees of the application are clear.

## Roadmap beyond v1

- SSRF-safe URL and redirect validation.
- Bounded HTTP requests and configurable network policies.
- Server-authoritative analysis persistence.
- Environment-specific cookie, CORS and deployment configuration.
- Bean Validation for API request contracts.
- Versioned database migrations.
- Paginated analysis history and lightweight list projections.
- Shared frontend session management and protected-route layout.
- Frontend component, integration and end-to-end tests.
- Dockerized local and production deployment.
- Configurable scoring policies and optional reputation providers.

## Project status

ThreatIntel Lite v1 is a consolidated first release: its main analysis, account, persistence and user-interface flows are implemented and backed by a comprehensive backend test suite.

Development after this milestone is focused on production hardening, operational configuration, performance and frontend test automation rather than completing the initial product workflow.

## Author

**Raúl Pérez Moreno**

Computer Engineering student at the University of Málaga, focused on Java, Spring Boot, networking, REST APIs and software architecture.

- [GitHub](https://github.com/raulperezmoreno71)
- [LinkedIn](https://www.linkedin.com/in/raul-perez-moreno/)
