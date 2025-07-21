package com.fastturtle.authserver.configs;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

//@Configuration
//public class AuthorizationServerConfig {
//
//    @Bean
//    @Order(1)
//    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
//        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
//
//        authorizationServerConfigurer
//                .oidc(Customizer.withDefaults())
//                .authorizationEndpoint(authEndpoint -> authEndpoint.consentPage("/oauth2/consent"));
//
//        http
//                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
//                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
//                .exceptionHandling(exceptions -> exceptions
//                        .accessDeniedHandler(customAccessDeniedHandler())
//                        .authenticationEntryPoint(customAuthenticationEntryPoint())
//                );
//
//        http.apply(authorizationServerConfigurer);
//
//        return http.build();
//    }
//
//    @Bean
//    @Order(2)
//    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .authorizeHttpRequests(authorize -> authorize
//                        .anyRequest().authenticated()
//                )
//                .formLogin(Customizer.withDefaults()); // ✅ Enables /login page
//
//        return http.build();
//    }
//
//
//    @Bean
//    public AccessDeniedHandler customAccessDeniedHandler() {
//        return (request, response, accessDeniedException) -> {
//            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
//            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
//            response.getWriter().write("{\"error\": \"access_denied\", \"error_description\": \"You denied the consent or lack permissions.\"}");
//        };
//    }
//
//    @Bean
//    public AuthenticationEntryPoint customAuthenticationEntryPoint() {
//        return (request, response, authException) -> {
//            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
//            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
//            response.getWriter().write("{\"error\": \"unauthorized\", \"error_description\": \"Authentication failed or required.\"}");
//        };
//    }
//}

@Configuration
public class AuthorizationServerConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer configurer =
                new OAuth2AuthorizationServerConfigurer();

        // Enable default login/consent UI but customize error responses
        configurer
                .authorizationEndpoint(authEndpoint -> authEndpoint
                        .errorResponseHandler(consentDenialHandler())
                )
                .oidc(Customizer.withDefaults());

        http
                .securityMatcher(configurer.getEndpointsMatcher())
                .authorizeHttpRequests(authz -> authz.anyRequest().authenticated())
                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/login")
                        .permitAll()
                )
                .apply(configurer);

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/login", "/error", "/webjars/**").permitAll()
                        .anyRequest().authenticated()
                )
                .exceptionHandling(exceptions -> exceptions
                        .accessDeniedHandler(apiAccessDeniedHandler())
                        .authenticationEntryPoint(apiAuthEntryPoint())
                );

        return http.build();
    }

    // Handler for when consent is denied
    private AuthenticationFailureHandler consentDenialHandler() {
        return (request, response, ex) -> {
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.getWriter().write("""
                {
                  "error": "consent_denied", 
                  "error_description": "User denied required permissions"
                }
                """);
        };
    }

    // Handler for API access without valid token
    private AuthenticationEntryPoint apiAuthEntryPoint() {
        return (request, response, ex) -> {
            // Return 401 with WWW-Authenticate header to trigger OAuth2 flow
            response.addHeader("WWW-Authenticate", "Bearer");
            response.sendError(HttpStatus.UNAUTHORIZED.value());
        };
    }

    // Handler for API access with insufficient scopes
    private AccessDeniedHandler apiAccessDeniedHandler() {
        return (request, response, ex) -> {
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.getWriter().write("""
                {
                  "error": "insufficient_scope",
                  "error_description": "Missing required scopes"
                }
                """);
        };
    }
}