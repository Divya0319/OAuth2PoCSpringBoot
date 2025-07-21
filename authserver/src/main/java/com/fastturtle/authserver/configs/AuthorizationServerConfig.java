package com.fastturtle.authserver.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

@Configuration
public class AuthorizationServerConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer configurer =
                new OAuth2AuthorizationServerConfigurer();

        configurer.oidc(Customizer.withDefaults());

        http
                .securityMatcher(configurer.getEndpointsMatcher())
                .authorizeHttpRequests(authz -> authz.anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                .exceptionHandling(exceptions -> exceptions
                        .accessDeniedHandler(customAccessDeniedHandler())
                )
                .apply(configurer);

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authz -> authz
                        .anyRequest().authenticated()
                )
                .formLogin(Customizer.withDefaults()) // This provides the default login page
                .exceptionHandling(exceptions -> exceptions
                        .accessDeniedHandler(customAccessDeniedHandler())
                );

        return http.build();
    }

    // Custom Access Denied Handler for JSON responses
    private AccessDeniedHandler customAccessDeniedHandler() {
        return (request, response, ex) -> {
            String acceptHeader = request.getHeader("Accept");
            String contentType = request.getHeader("Content-Type");

            // Check if it's an API request (JSON) or has API in path
            boolean isApiRequest = (acceptHeader != null && acceptHeader.contains("application/json")) ||
                    (contentType != null && contentType.contains("application/json")) ||
                    request.getRequestURI().startsWith("/api/") ||
                    request.getRequestURI().contains("/oauth2/") ||
                    request.getRequestURI().contains("/token");

            if (isApiRequest) {
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.setStatus(HttpStatus.FORBIDDEN.value());
                response.getWriter().write("""
                    {
                      "error": "access_denied",
                      "error_description": "Access denied - insufficient privileges",
                      "status": 403,
                      "timestamp": "%s"
                    }
                    """.formatted(java.time.Instant.now().toString()));
            } else {
                // For browser requests, you can still redirect or show a simple message
                response.setContentType("text/html");
                response.setStatus(HttpStatus.FORBIDDEN.value());
                response.getWriter().write("""
                    <html>
                    <body>
                        <h2>Access Denied</h2>
                        <p>You don't have sufficient privileges to access this resource.</p>
                        <a href="/login">Go to Login</a>
                    </body>
                    </html>
                    """);
            }
        };
    }
}
