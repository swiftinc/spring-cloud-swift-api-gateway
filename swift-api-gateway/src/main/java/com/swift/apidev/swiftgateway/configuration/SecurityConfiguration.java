package com.swift.apidev.swiftgateway.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;

import com.swift.apidev.swiftgateway.security.HeaderAuthenticationConverter;
import com.swift.apidev.swiftgateway.security.HeaderAuthenticationManager;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfiguration {

    @Bean
    SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http,
            AuthenticationWebFilter authenticationWebFilter) {

        // Disable default security
        http.csrf(ServerHttpSecurity.CsrfSpec::disable);
        http.httpBasic(ServerHttpSecurity.HttpBasicSpec::disable);
        http.formLogin(ServerHttpSecurity.FormLoginSpec::disable);
        http.logout(ServerHttpSecurity.LogoutSpec::disable);

        http.authorizeExchange(
                exchanges -> exchanges.pathMatchers("/actuator/**").permitAll().anyExchange().authenticated())
                .addFilterAt(authenticationWebFilter, SecurityWebFiltersOrder.AUTHENTICATION);

        return http.build();
    }

    /**
     * Add authentication filter to extract principal from 'X-Consumer-Custom-ID'
     * HTTP header.
     * This is needed to use the
     * {@link org.springframework.cloud.gateway.filter.factory.TokenRelayGatewayFilterFactory}
     * to relay the token to downstream services.
     * 
     * Without this filter, the token will not be relayed.
     */
    @Bean
    AuthenticationWebFilter authenticationWebFilter(HeaderAuthenticationManager headerAuthenticationManager,
            HeaderAuthenticationConverter headerAuthenticationConverter) {
        final AuthenticationWebFilter authenticationWebFilter = new AuthenticationWebFilter(
                headerAuthenticationManager);
        authenticationWebFilter.setServerAuthenticationConverter(headerAuthenticationConverter);
        return authenticationWebFilter;
    }
}
