package com.swift.apidev.swiftgateway.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

@Component
public class HeaderAuthenticationConverter implements ServerAuthenticationConverter {
    private static final String HEADER_NAME = "X-Consumer-Custom-ID";

    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        return Mono.justOrEmpty(exchange)
                .mapNotNull(serverWebExchange -> serverWebExchange.getRequest().getHeaders().getFirst(HEADER_NAME))
                .flatMap(this::createAuthentication);
    }

    private Mono<HeaderAuthenticationToken> createAuthentication(String value) {
        HeaderAuthenticationToken headerAuthenticationToken = new HeaderAuthenticationToken(value);
        return Mono.just(headerAuthenticationToken);
    }
}
