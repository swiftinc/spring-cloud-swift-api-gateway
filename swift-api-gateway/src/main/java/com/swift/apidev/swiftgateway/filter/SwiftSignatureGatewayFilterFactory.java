package com.swift.apidev.swiftgateway.filter;

import java.util.Arrays;
import java.util.List;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.swift.apidev.swiftgateway.oauth2.JwtOperations;

import reactor.core.publisher.Flux;

@Component
public class SwiftSignatureGatewayFilterFactory
        extends AbstractGatewayFilterFactory<AbstractGatewayFilterFactory.NameConfig> {

    private static final String SWIFT_SIGNATURE_HEADER = "X-SWIFT-Signature";

    final JwtOperations jwtOperations;

    public SwiftSignatureGatewayFilterFactory(JwtOperations jwtOperations) {
        super(NameConfig.class);
        this.jwtOperations = jwtOperations;
    }

    @Override
    public GatewayFilter apply(NameConfig config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            HttpMethod method = exchange.getRequest().getMethod();
            if (method == HttpMethod.POST || method == HttpMethod.PUT) {
                return DataBufferUtils.join(request.getBody()).flatMap(dataBuffer -> {
                    // Read the request body
                    final byte[] payload = new byte[dataBuffer.readableByteCount()];
                    dataBuffer.read(payload);
                    DataBufferUtils.release(dataBuffer);

                    // Calculate the signature
                    final String url = request.getURI().getPath();
                    final String swiftSignature = jwtOperations.generateSignature(config.getName(), url,
                            payload);

                    // Inject the signature into the request header
                    ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
                            .header(SWIFT_SIGNATURE_HEADER, swiftSignature)
                            .build();

                    DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(payload);
                    ServerHttpRequest modifiedRequestDecorator = new ServerHttpRequestDecorator(modifiedRequest) {
                        @Override
                        public @NonNull Flux<DataBuffer> getBody() {
                            return Flux.just(buffer);
                        }
                    };

                    ServerWebExchange newExchange = exchange.mutate()
                            .request(modifiedRequestDecorator)
                            .build();

                    return chain.filter(newExchange);
                });
            } else {
                return chain.filter(exchange);
            }
        };
    }

    @Override
    public List<String> shortcutFieldOrder() {
        return Arrays.asList(NAME_KEY);
    }
}