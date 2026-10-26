# ThreatIntel Lite

[![CI/CD](https://github.com/raulperezmoreno71/threatintel-lite/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/raulperezmoreno71/threatintel-lite/actions/workflows/ci-cd.yml)

ThreatIntel Lite is a full-stack web application that analyzes the technical security posture of a URL and presents the result as a structured, readable report.

The application combines a Java 21 and Spring Boot REST API with a React and TypeScript client. Authenticated users can run URL analyses, inspect DNS, HTTP, redirect, TLS and security-header information, calculate an overall score, and save selected reports to a private history backed by PostgreSQL.

## Live demo

[Open ThreatIntel Lite](https://threatintel.raulperezmoreno.dev/)

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
- Public-destination validation for IPv4 and IPv6, including every redirect target.
- Standard destination ports only: HTTP on port `80` and HTTPS on port `443`.
- Domain extraction and DNS resolution.
- Collection of all resolved IP addresses.
- Manual redirect tracking for `301`, `302`, `303`, `307` and `308` responses.
- Relative redirect resolution and a maximum redirect limit.
- Final HTTP status, URL, content type, server and declared content length.
- Response time for each request and for the complete redirect chain.
- Response-header inspection without downloading the response body.
- A configurable time budget shared by the complete analysis pipeline.
- Per-user analysis rate limiting: 5 admitted requests per rolling 60-second window by default.

### TLS certificate analysis

- Certificate issuer and subject.
- Validity start and end dates.
- Remaining days until expiration.
- `GOOD`, `WARNING` or `CRITICAL` classification.
- Renewal recommendation when the certificate is close to expiration or expired.
- Explicit timeout, handshake and general TLS error handling.
- Connections pinned to validated IP addresses while preserving the original hostname for SNI and certificate verification.

TLS analysis is omitted for plain HTTP destinations.

### Outbound network safeguards

Every HTTP destination is validated before connecting, including destinations reached through relative or absolute redirects. The validator rejects private, loopback, link-local, multicast and other blocked or non-public address ranges. A hostname is rejected if any of its resolved addresses is disallowed; nonstandard destination ports are also rejected.

`ValidatedUrl` carries an immutable snapshot of the approved IP addresses. `PinnedHttpTransport` uses Apache HttpClient 5 with a destination-specific DNS resolver to connect only to that snapshot, avoiding a second unrestricted DNS lookup at connection time. The original hostname remains in the request and TLS identity checks. Automatic redirects, retries, cookie management and content decompression are disabled in this transport; redirect handling stays in the analysis layer, where each hop is validated again.

The transport collects status and headers, then closes the connection without consuming the response body. The separate TLS inspection also connects to approved IP addresses and enables HTTPS hostname verification and SNI.

| Control | Current value or behaviour |
|---|---|
| Complete analysis budget | `15000` ms by default, configurable with `app.analysis.timeout-ms` |
| HTTP connection and socket timeouts | Up to `5000` ms, capped by the remaining analysis budget |
| TLS connection and socket timeouts | Up to `5000` ms, capped by the remaining analysis budget |
| Redirect limit | 10 redirects after the initial request |
| DNS concurrency | 4 resolver workers and a bounded queue of 16 tasks |
| Deadline expiry | Active HTTP requests are cancelled and TLS sockets are closed |
| DNS capacity exhaustion | New work is rejected with `503 Service Unavailable` |

The DNS deadline bounds how long the analysis waits. A native DNS lookup may ignore thread interruption and continue in a worker; the bounded worker pool and queue prevent unlimited resolver task accumulation.

### Per-user analysis rate limiting

`POST /api/analyze` is limited by the authenticated user's database ID. By default, each user can start up to **5 analysis requests in any rolling 60-second window**. The next request returns `429 Too Many Requests` before the analysis pipeline runs. Each user has an independent allowance; this does not limit the number of registered accounts.

Admission is checked before URL validation and outbound network work. An admitted request consumes a slot even if the analysis later fails or the URL is rejected. Rate-limited requests do not consume additional slots or extend the window. Slots become available individually as earlier attempts reach the configured age, rather than resetting at fixed clock-minute boundaries.

`AnalysisRateLimitService` synchronizes admission checks to enforce the limit for concurrent requests within one backend instance. It removes inactive user entries with a scheduled cleanup every 60 seconds; expired attempts are also discarded during admission, so recovery does not depend on waiting for cleanup.

Counters are stored in memory. Restarting the backend resets them, and multiple backend instances do not share the same counters. The policy applies only to URL analysis, not registration, login or other API endpoints.

### HTTP security assessment

ThreatIntel Lite evaluates six response headers:

- `Strict-Transport-Security`
- `Content-Security-Policy`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`

Every header receives a status, its detected value and an actionable recommendation when improvement is needed. The results are combined into a weighted score and an overall grade.

The score is based only on these six headers; DNS results, HTTP response codes and TLS certificate status are reported separately and do not add or subtract points.

| Header | Maximum points |
|---|---:|
| `Content-Security-Policy` | 30 |
| `Strict-Transport-Security` | 20 |
| `X-Content-Type-Options` | 15 |
| `X-Frame-Options` | 15 |
| `Referrer-Policy` | 10 |
| `Permissions-Policy` | 10 |

`GOOD` earns the full weight, `WARNING` earns half rounded to the nearest integer, and `MISSING` earns zero points.

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
- CSRF protection using the `XSRF-TOKEN` cookie and `X-XSRF-TOKEN` request header.
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
    │ JSON + HttpOnly authentication cookie + CSRF header
    ▼
Spring Security / CSRF and JWT filters
    │
    ▼
REST controllers
    │
    ├── Account service ───────────────► User repository
    │
    ├── Analysis coordinator
    │       ├── Public URL / IP validation
    │       ├── DNS analysis
    │       ├── Pinned HTTP connections and validated redirects
    │       ├── Pinned TLS certificate analysis
    │       └── Security-header scoring
    │
    └── Analysis history service ─────► Analysis repository
                                            │
                                            ▼
                                       PostgreSQL
```

The analysis operation and persistence are intentionally separate in v1. A report is generated first and is only persisted when the user chooses **Save analysis**.

One `AnalysisDeadline` is passed through URL validation, DNS resolution, HTTP redirects and TLS inspection. Each stage consumes the remaining budget instead of restarting an independent full-analysis timeout.

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
├── test/         Shared test helpers and reusable fixtures
├── App.tsx       Application routes
├── entry-server.tsx  Static rendering entry for the public landing page
├── main.tsx      React entry point
└── types.ts      Shared API response types
```

The public landing page is pre-rendered into `dist/index.html` during the production build, so its content and links are present in the initial HTML response. React hydrates that page for navigation and interaction. Authentication and private routes use the client-rendered `dist/app.html` shell with `noindex`. React Router manages navigation and the browser sends the authentication cookie using `credentials: "include"`.

The production web server must serve `index.html` only for `/`, serve `app.html` for the known application routes, and return HTTP 404 for unknown routes. Nginx routing and the VPS deployment script are managed on the server; validate configuration changes with `nginx -t` before reloading. The deployment workflow uploads the complete frontend artifact. The build also copies `robots.txt`, `sitemap.xml`, the social preview image and `404.html` from `frontend/public`.

## Technology stack

| Area | Technology |
|---|---|
| Backend language | Java 21 |
| Backend framework | Spring Boot 4 |
| Web and security | Spring MVC, Spring Security, JWT |
| Persistence | Spring Data JPA, Hibernate |
| Database | PostgreSQL |
| Networking | Apache HttpClient 5 with pinned DNS resolution, Java HTTP response models, DNS APIs and JSSE |
| API documentation | SpringDoc OpenAPI / Swagger UI |
| Frontend | React 19, TypeScript 6, React Router 7 |
| Build tooling | Maven Wrapper, Vite 8, npm |
| Backend testing | JUnit 5, Mockito, MockMvc, Testcontainers |
| Frontend testing | Vitest, React Testing Library, jest-dom, JSDOM |
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

### CSRF and authentication

Spring Security's SPA CSRF configuration issues a readable `XSRF-TOKEN` cookie. The frontend API client copies its value to `X-XSRF-TOKEN` and sends cookies with `credentials: "include"`. Spring validates CSRF tokens on unsafe methods such as `POST` and `DELETE`, including the public registration, login and logout endpoints. Public access in the table means that a JWT is not required; it does not exempt a request from CSRF validation.

For manual API calls, first make a safe request such as `GET /api/health`, retain the response cookies, and copy the `XSRF-TOKEN` value into the header of subsequent unsafe requests. After login, also retain the `access_token` cookie. Missing or mismatched CSRF tokens normally result in `403 Forbidden`.

The JWT expires after one hour with the current `jwt.expiration=3600000` setting. The CSRF token has a separate lifecycle and is not the user's authentication credential.

### Authentication example

Register an account:

```http
POST /api/auth/register
Content-Type: application/json
Cookie: XSRF-TOKEN=<csrf-token>
X-XSRF-TOKEN: <csrf-token>

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
Cookie: XSRF-TOKEN=<csrf-token>
X-XSRF-TOKEN: <csrf-token>

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
Cookie: access_token=<jwt>; XSRF-TOKEN=<csrf-token>
X-XSRF-TOKEN: <csrf-token>

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

The example uses illustrative values and is abbreviated: a real response contains the result of all six security-header checks. HTTP response times cover the outbound request through receipt of its headers; the body is not downloaded. `contentLength` is the server's declared header value, not a measured body size.

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

Common responses include `400 Bad Request`, `401 Unauthorized`, `403 Forbidden`, `404 Not Found`, `409 Conflict` and `500 Internal Server Error`. The JSON contract above describes controller/advice and authentication-entry-point errors; security-filter errors such as CSRF rejection may use a different response representation.

The analysis endpoint also exposes these explicit resource-limit responses:

| Status | Message | Meaning |
|---|---|---|
| `429 Too Many Requests` | `Too many analysis request. Please try again later.` | The user's rolling analysis allowance has been exhausted |
| `503 Service Unavailable` | `DNS resolver is busy; try again later` | All resolver workers and queue slots are occupied |
| `504 Gateway Timeout` | `Analysis time limit exceeded` | The shared analysis budget has expired |

Rejected URL schemes, ports or destination IP addresses return `400 Bad Request`. An individual network or TLS failure can occur before the overall deadline and is handled separately; not every network timeout produces `504`.

A rate-limit rejection uses the standard error contract:

```json
{
  "status": 429,
  "error": "Too Many Requests",
  "message": "Too many analysis request. Please try again later.",
  "path": "/api/analyze"
}
```

The current response does not include a `Retry-After` header. A new request can be admitted once an earlier attempt leaves the rolling window.

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
- Node.js `22.22.2` or later in the 22.x line, or `24.15.0` or later in the 24.x line, and npm (required by the installed JSDOM test dependency)
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

### Backend profiles and limits

The default profile is configured for local development. Activate the production profile with `SPRING_PROFILES_ACTIVE=prod` when deploying the backend.

| Property | Default profile | `prod` profile |
|---|---|---|
| `app.cookie.secure` | `false` | `true` |
| `app.cors.allowed-origin` | `http://localhost:5173` | `https://threatintel.raulperezmoreno.dev` |
| `app.analysis.timeout-ms` | `15000` | Inherits the default unless overridden |
| `app.analysis.rate-limit.max-requests` | `5` | Inherits the default unless overridden |
| `app.analysis.rate-limit.window-seconds` | `60` | Inherits the default unless overridden |
| `spring.jpa.hibernate.ddl-auto` | `update` | `update` |

The analysis timeout must be positive. For a 20-second budget, set the following property in the active Spring Boot configuration:

```properties
app.analysis.timeout-ms=20000
```

The same setting can be supplied as the application argument `--app.analysis.timeout-ms=20000` when running the packaged JAR. CORS and authentication-cookie security can be overridden with `APP_CORS_ALLOWED_ORIGIN` and `APP_COOKIE_SECURE`.

Both rate-limit settings must be positive. Configure the number of admitted requests and the rolling-window duration independently, for example:

```properties
app.analysis.rate-limit.max-requests=5
app.analysis.rate-limit.window-seconds=60
```

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
npm ci
npm run dev
```

The Vite development server starts at `http://localhost:5173`. `frontend/.env.development` sets `VITE_API_URL=http://localhost:8080`, matching the backend's local CORS configuration. Without `VITE_API_URL`, the API client uses relative URLs for same-origin deployment.

## Testing and quality checks

### Backend

The backend automated test suite covers:

- URL, DNS, HTTP, redirect, TLS and security-header analysis.
- SSRF destination rules, blocked IPv4/IPv6 ranges, ports and redirect validation.
- Pinned-IP HTTP connections, isolated DNS snapshots and original-host preservation.
- Real local TLS handshakes, SNI, hostname verification and certificate trust failures.
- Header-only HTTP handling without waiting for response bodies.
- Shared deadlines, slow headers, cancelled TLS operations and DNS queue saturation.
- Per-user rate limits, rolling-window expiry, rejected attempts, concurrent admission and scheduled cleanup.
- Controller/rate-limiter integration, including `429` responses, independent user allowances and counting failed analyses.
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

Network integration tests use controlled local HTTP/TLS peers and test-only certificate fixtures. These fixtures inject destinations at the transport boundary; they do not relax production URL validation or trust settings. The test certificate and its public test credentials are documented in `backend/src/test/resources/tls/README.md`.

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

The frontend automated test suite covers:

- Registration, login and password-change forms.
- Session checks, expiration handling and logout flows.
- URL analysis, pending requests and API error states.
- Analysis result rendering, saving and discard confirmation.
- Saved-analysis list, empty, loading and error states.
- Saved-analysis detail loading and route-parameter validation.
- Landing-page content, calls to action and navigation links.
- Accessible names, status messages and relevant ARIA state.

Run the complete test suite, static checks and production build from `frontend`:

```bash
npm run test:run
npm run lint
npm run build
```

For an interactive Vitest watch session during development, run:

```bash
npm test
```

The `CI/CD` GitHub Actions workflow runs backend and frontend checks independently for pull requests and pushes to `main`. The backend job executes the Maven test suite; the frontend job installs locked dependencies with `npm ci` and runs Vitest, ESLint and the production build.

On a push to `main`, deployment runs only after both jobs pass. It packages the backend JAR, builds the frontend including pre-rendering, transfers the artifacts to the VPS over SSH, and invokes the server's deployment script. This job requires the repository secrets `VPS_HOST`, `VPS_USER` and `VPS_SSH_KEY`, plus the corresponding staging directories and deployment script on the server.

## Current v1 boundaries

Version 1 includes public-destination validation, pinned outbound connections, shared analysis deadlines, per-user analysis rate limiting, CSRF protection and a production configuration profile. The following boundaries remain:

- Analysis persistence currently accepts the completed report returned by the client.
- Request DTOs do not yet have comprehensive Bean Validation constraints.
- Analysis rate-limit counters are local to each backend instance and reset on restart. Shared counters and application-wide throttling for other endpoints are not implemented.
- A native DNS lookup can outlive the caller's deadline; resolver capacity is bounded and overload is reported explicitly.
- Invalid or untrusted HTTPS certificates can stop the analysis during the HTTP handshake before a certificate report is produced.
- Database schema changes currently rely on Hibernate rather than versioned migrations.
- Saved-analysis listings are not paginated.
- End-to-end browser tests are planned for a later iteration.

These constraints are documented explicitly so that the current guarantees of the application are clear.

## Roadmap beyond v1

- Shared rate-limit counters for multi-instance deployments and throttling for other endpoints.
- Further operational tuning of network limits and resolver capacity.
- Server-authoritative analysis persistence.
- Bean Validation for API request contracts.
- Versioned database migrations.
- Paginated analysis history and lightweight list projections.
- Shared frontend session management and protected-route layout.
- End-to-end browser tests for the main user journeys.
- Dockerized local and production deployment.
- Configurable scoring policies and optional reputation providers.

## Project status

ThreatIntel Lite v1 is a consolidated first release: its main analysis, account, persistence and user-interface flows are implemented and backed by comprehensive backend and frontend test suites.

The current backend adds network safeguards and deadline enforcement to that baseline. Further development focuses on authoritative persistence, input validation, database migrations, operational observability, performance and end-to-end browser coverage.

## Author

**Raúl Pérez Moreno**

Computer Engineering student at the University of Málaga, focused on Java, Spring Boot, networking, REST APIs and software architecture.

- [GitHub](https://github.com/raulperezmoreno71)
- [LinkedIn](https://www.linkedin.com/in/raul-perez-moreno/)
