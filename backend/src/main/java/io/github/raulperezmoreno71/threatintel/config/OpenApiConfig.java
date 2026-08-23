package io.github.raulperezmoreno71.threatintel.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI threatIntelOpenAPI () {
        return new OpenAPI()
                .info(
                        new Info()
                                .title("ThreatIntel Lite API")
                                .version("0.1.0")
                                .description(
                                        "REST API for DNS resolution, HTTP analysis, redirect chain inspection, SSL/TLS certificate analysis and HTTP security header assessment."
                                )
                                .contact(
                                        new Contact()
                                                .name("Raúl Pérez Moreno")
                                                .url("https://github.com/raulperezmoreno71")
                                )

                );
    }
}
