package com.swift.apidev.swiftgateway.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.http.codec.FormHttpMessageWriter;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.client.AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.JwtBearerReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveJwtBearerTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.web.reactive.function.client.ExchangeStrategies;
import org.springframework.web.reactive.function.client.WebClient;

import com.swift.apidev.swiftgateway.oauth2.JwtOperations;

import reactor.netty.http.client.HttpClient;

/**
 * This configuration is used to configure OAuth2 client manager and
 * OAuth2 client provider.**
 *
 * @see <a href=
 *      "https://docs.spring.io/spring-security/reference/reactive/oauth2/client/index.html">Spring
 *      Boot OAuth 2.0 client</a>
 */
@Configuration
public class OAuth2Configuration {

    @Bean
    AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager clientManager(
            ReactiveClientRegistrationRepository clientRegistrations,
            ReactiveOAuth2AuthorizedClientService authorizedClientRepository,
            ReactiveOAuth2AuthorizedClientProvider clientProvider) {
        var authorizedClientManager = new AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager(
                clientRegistrations,
                authorizedClientRepository);
        authorizedClientManager.setAuthorizedClientProvider(clientProvider);
        return authorizedClientManager;
    }

    @Bean
    ReactiveOAuth2AuthorizedClientProvider oauth2ClientProvider(
            WebClientReactiveJwtBearerTokenResponseClient tokenResponseClient,
            JwtOperations jwtOperations) {
        var jwtBearerProvider = new JwtBearerReactiveOAuth2AuthorizedClientProvider();
        jwtBearerProvider.setAccessTokenResponseClient(tokenResponseClient);
        jwtBearerProvider.setJwtAssertionResolver(jwtOperations::assertion);
        return ReactiveOAuth2AuthorizedClientProviderBuilder
                .builder()
                .provider(jwtBearerProvider)
                .build();
    }

    @Bean
    WebClientReactiveJwtBearerTokenResponseClient tokenResponseClient(WebClient webClient) {
        var tokenResponseClient = new WebClientReactiveJwtBearerTokenResponseClient();
        tokenResponseClient.setWebClient(webClient);
        return tokenResponseClient;
    }

    @Bean
    WebClient webClient(HttpClient httpClient) {
        return WebClient.builder()
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .exchangeStrategies(exchangeStrategies())
                .build();
    }

    /**
     * Workaround to set media type to application/x-www-form-urlencoded without
     * charset for Swift API gateway
     */
    private ExchangeStrategies exchangeStrategies() {
        // Swift API gateway does not support media type + encoding.
        // Create a strategy to only use application/x-www-form-urlencoded media type
        return ExchangeStrategies.builder()
                .codecs(configurer -> {
                    configurer.registerDefaults(true);
                    configurer.customCodecs().register(new FormHttpMessageWriter() {
                        @Override
                        protected @NonNull MediaType getMediaType(@Nullable MediaType mediaType) {
                            // Always return application/x-www-form-urlencoded without charset
                            return MediaType.APPLICATION_FORM_URLENCODED;
                        }
                    });
                }).build();
    }
}
