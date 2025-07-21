package com.fastturtle.authclient.config;

import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

@EnableWebFluxSecurity
public class GatewaySecurityConfig {

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http.authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/error-page").permitAll()
                        .anyExchange().authenticated()
        )
                .oauth2Login(oauth2 -> oauth2
                        .authenticationFailureHandler(customFailureHandler())
                )
                .exceptionHandling(exceptions -> exceptions
                        .accessDeniedHandler(customAccessDeniedHandler())
                        .authenticationEntryPoint(customAuthenticationEntryPoint()))
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
        ;

        return http.build();
    }

    public ServerAuthenticationFailureHandler customFailureHandler() {
        return (exchange, exception) -> {
            // Redirect to custom error endpoint
            return exchange.getExchange().getResponse()
                    .setComplete()
                    .then(Mono.fromRunnable(() -> {
                        exchange.getExchange().getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                    }));
        };
    }

    @Bean
    public ServerAccessDeniedHandler customAccessDeniedHandler() {
        return (exchange, denied) -> {
            ServerHttpResponse response = exchange.getResponse();
            response.setStatusCode(HttpStatus.FORBIDDEN);
            response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
            byte[] bytes = "{\"error\":\"Forbidden\", \"message\":\"Access denied or consent cancelled.\"}"
                    .getBytes(StandardCharsets.UTF_8);
            return response.writeWith(Mono.just(response.bufferFactory().wrap(bytes)));
        };
    }

    @Bean
    public ServerAuthenticationEntryPoint customAuthenticationEntryPoint() {
        return (exchange, ex) -> {
            ServerHttpResponse response = exchange.getResponse();
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
            byte[] bytes = "{\"error\":\"Unauthorized\", \"message\":\"Authentication is required.\"}"
                    .getBytes(StandardCharsets.UTF_8);
            return response.writeWith(Mono.just(response.bufferFactory().wrap(bytes)));
        };
    }
}

