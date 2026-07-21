# ThreatIntel Lite

## Overview

ThreatIntel Lite is a REST API built with Spring Boot that analyzes different aspects of a URL and returns the results grouped into dedicated analysis modules, including DNS resolution, HTTP behavior, SSL/TLS certificate information and HTTP security headers.

The project is designed to explore how backend applications interact with Internet protocols such as DNS and HTTP while following clean architecture principles and modern Java development practices.

ThreatIntel Lite is being developed incrementally, with each feature focusing on understanding a specific backend or networking concept rather than simply adding functionality.

## Features

 - [x] Validate HTTP and HTTPS URLs.
 - [x] Extract the domain from a URL.
 - [x] Resolve all available IP addresses through DNS.
 - [x] Retrieve the HTTP status code.
 - [x] Detect HTTP redirections and their destination.
 - [x] Detect the response Content-Type.
 - [x] Identify the responding web server.
 - [x] Retrieve the declared Content-Length header.
 - [x] Measure the HTTP response time.
 - [x] Handle invalid requests through global exception handling.
 - [x] Analyze SSL/TLS certificates.
 - [x] Retrieve certificate issuer and subject.
 - [x] Retrieve certificate validity dates.
 - [x] Calculate remaining days until certificate expiration.
 - [x] Analyze common HTTP security headers.
 - [x] Detect the presence of important security headers.
 - [x] Retrieve the value of each detected security header.
 - [x] Return structured JSON responses grouped by analysis module.
 - [x] Follow HTTP redirect chains manually.
 - [x] Measure response time for each redirect.
 - [x] Identify the final destination URL.
 - [x] Follow a clean layered architecture (Controller, Service, DTO and Exception Handler).

## Tech Stack

 - **Language:** Java 21
 - **Framework:** Spring Boot
 - **Build Tool:** Maven
 - **Networking:** Java HttpClient, JSSE (SSL/TLS)
 - **JSON Serialization:** Jackson
 - **Version Control:** Git
 - **Repository Hosting:** GitHub

## Project Structure

```text
src
└── main
    └── java
        └── io.github.raulperezmoreno71.threatintel
            ├── controller
            ├── dto
            ├── exception
            ├── model
            └── service
```

### `controller`

Receives incoming HTTP requests, delegates the processing to the service layer and returns the API response.

### `service`

Contains the application's business logic, including URL validation, DNS resolution and HTTP analysis.

### `dto`

Defines the request and response objects exchanged between the API and its clients.

### `model`

Contains internal domain models that represent the results of the different analysis modules, including DNS, HTTP, SSL/TLS and Security Headers.

### `exception`

Provides centralized exception handling and returns consistent error responses.

The project follows a layered architecture, keeping responsibilities separated to improve readability, maintainability and scalability.

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
    "totalResponseTimeMs": 487,
    "redirectChain": [
      {
        "url": "https://github.com/",
        "statusCode": 200,
        "location": null,
        "responseTimeMs": 487
      }
    ]
  },
  "ssl": {
    "issuer": "CN=Sectigo Public Server Authentication CA DV E36,O=Sectigo Limited,C=GB",
    "subject": "CN=github.com",
    "validFrom": "2026-07-03",
    "validUntil": "2026-09-30",
    "daysUntilExpiration": 71
  },
  "securityHeaders": {
    "strictTransportSecurity": {
      "present": true,
      "value": "max-age=31536000; includeSubdomains; preload"
    },
    "contentSecurityPolicy": {
      "present": true,
      "value": "default-src 'none'; base-uri 'self'; ... .com/assets-cdn/worker/"
    },
    "xFrameOptions": {
      "present": true,
      "value": "deny"
    },
    "xContentTypeOptions": {
      "present": true,
      "value": "nosniff"
    },
    "referrerPolicy": {
      "present": true,
      "value": "origin-when-cross-origin, strict-origin-when-cross-origin"
    },
    "permissionsPolicy": {
      "present": false,
      "value": null
    }
  }
}
```

**Validation Error**

```json
{
    "status": 400,
    "error": "Bad Request",
    "message": "URL cannot be null or blank",
    "path": "/api/analyze"
}
```

## Getting Started

### Prerequisites

Before running the project, make sure you have installed:

 - Java 21
 - Maven
 - Git

### Clone the repository

```bash
git clone https://github.com/raulperezmoreno71/threatintel-lite.git
cd threatintel-lite
```

### Run the application

```bash
mvn spring-boot:run
```

By default, the application will start on:

```text
http://localhost:8080
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

## Roadmap

The project is being developed incrementally, with each milestone focused on learning and implementing a specific backend or networking concept.

### Completed
 - [x] URL validation
 - [x] DNS resolution
 - [x] HTTP status code analysis
 - [x] HTTP redirection detection
 - [x] HTTP response header analysis
 - [x] HTTP security headers analysis
 - [x] HTTP response time measurement
 - [x] Global exception handling
 - [x] SSL/TLS certificate analysis
 - [x] Modular JSON response structure
 - [x] Redirect chain analysis

### Planned

 - [ ] REST API documentation (OpenAPI / Swagger)
 - [ ] Unit and integration tests
 - [ ] Docker support
 - [ ] Authentication and user accounts
 - [ ] Persistent analysis history
 - [ ] Domain reputation analysis using external services

## Author

**Raúl Pérez Moreno**

Computer Engineering student at the University of Málaga (UMA), currently building backend projects with Java and Spring Boot, focusing on networking, REST APIs and software architecture.

 - Github: https://github.com/raulperezmoreno71/
 - LinkedIn: https://www.linkedin.com/in/ra%C3%BAl-p%C3%A9rez-moreno-ba0aab3a7/