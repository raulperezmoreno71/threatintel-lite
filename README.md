# ThreatIntel Lite

## Overview

ThreatIntel Lite is a Rest API built with Spring Boot that analyzes different aspects of a URL, including domain  resolution, HTTP responses and redirection behavior.

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
 - [x] Return structured JSON responses.
 - [x] Handle invalid request through global exception handling.
 - [x] Follow a clean layered architecture (Controller, Service, DTO and Exception Handler).

## Tech Stack

 - **Language:** Java 21
 - **Framework:** Spring Boot
 - **Build Tool:** Maven
 - **HTTP Client:** Java HttpClient
 - **JSON Serialization:** Jackson
 - **Version Control:** Git
 - **Repository Hosting:** GitHub

## Project Structure

```text
src
└── main
    └──java
        └──io.github.raulperezmoreno71.threatintel
            ├── controller
            ├── dto
            ├── exception
            └── service
```

### `controller`

Receives incoming HTTP requests, delegates the processing to the service layer and returns the API response.

### `service`

Contains the application's business logic, including URL validation, DNS resolution and HTTP analysis.

### `dto`

Defines the request and response objects exchanged between the API and its clients.

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
    "url": "https://google.com"
}
```

**Successful Response**

```json
{
    "message": "URL analyzed successfully",
    "url": "https://google.com",
    "domain": "google.com",
    "ips": [
        "216.58.205.46"
    ],
    "httpStatusCode": 301,
    "redirectLocation": "https://www.google.com",
    "contentType": "text/html; charset=UTF-8",
    "server": "gws",
    "contentLength": 220
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
 - [x] Domain extraction
 - [x] DNS resolution
 - [x] HTTP status code analysis
 - [x] HTTP redirection detection
 - [x] HTTP response header analysis
 - [x] Global exception handling
 - [x] Structures JSON responses

### Planned

 - [ ] HTTP response time measurement
 - [ ] SSL/TLS certificate analysis
 - [ ] Redirect chain analysis
 - [ ] Security headers analysis
 - [ ] REST API documentation (OpenAPI / Swagger)
 - [ ] Unit and integration tests
 - [ ] Docker support
 - [ ] Domain reputation analysis using external services.

## Author

**Raúl Pérez Moreno**

Computer Engineering student at the University of Málaga (UMA), passionate about backend development, networking and software engineering.

 - Github: https://github.com/raulperezmoreno71/
 - LinkedIn: https://www.linkedin.com/in/ra%C3%BAl-p%C3%A9rez-moreno-ba0aab3a7/