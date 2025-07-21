package com.fastturtle.authclient.config;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.GatewayFilterSpec;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class GatewayRoutesConfig {

    @Bean
    RouteLocator gateway(RouteLocatorBuilder rlb) {
        return rlb.routes()
                .route("hello", rs -> rs
                        .path("/hello")
                        .filters(GatewayFilterSpec::tokenRelay)
                        .uri("http://localhost:8081"))
                .route("coders", rs -> rs
                        .path("/api/coders")
                        .filters(GatewayFilterSpec::tokenRelay)
                        .uri("http://localhost:8000")
                )
                .build();
    }
}
