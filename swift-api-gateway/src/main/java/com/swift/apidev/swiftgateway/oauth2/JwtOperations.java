package com.swift.apidev.swiftgateway.oauth2;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.swift.apidev.swiftgateway.configuration.SwiftProperties;

import reactor.core.publisher.Mono;

@Component
public class JwtOperations {
    private static final Logger LOG = LoggerFactory.getLogger(JwtOperations.class);

    final SwiftProperties swiftProperties;

    public JwtOperations(SwiftProperties swiftProperties) {
        this.swiftProperties = swiftProperties;
    }

    public Mono<Jwt> assertion(OAuth2AuthorizationContext oAuth2AuthorizationContext) {
        final ClientRegistration clientRegistration = oAuth2AuthorizationContext.getClientRegistration();
        final String clientName = clientRegistration.getClientName();

        // Get client configuration from swift properties
        final SwiftProperties.ChannelCertificate channelCertificate = swiftProperties
                .getChannelCertificates()
                .get(clientName);

        if (channelCertificate == null) {
            throw new RuntimeException("No channel certificate found with name: " + clientName);
        }

        // Audience is token URL without https://
        final String tokenUri = clientRegistration.getProviderDetails().getTokenUri();
        final String audience = tokenUri.substring("https://".length());

        try {
            X509Certificate certificate = channelCertificate.x509Certificate();
            PrivateKey privateKey = channelCertificate.privateKey();

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .x509CertChain(
                            Collections.singletonList(Base64.encode(certificate.getEncoded())))
                    .type(JOSEObjectType.JWT).build();

            Instant issuedAt = Instant.now();
            Instant expiresAt = issuedAt.plus(Duration.ofSeconds(15));

            // @formatter:off
            JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                    .subject(certificate.getSubjectX500Principal().getName())
                    .jwtID(UUID.randomUUID().toString())
                    .notBeforeTime(Date.from(issuedAt))
                    .issueTime(Date.from(issuedAt))
                    .expirationTime(Date.from(expiresAt))
                    .issuer(clientRegistration.getClientId())
                    .audience(Collections.singletonList(audience))
                    .build();
            // @formatter:on

            SignedJWT signedJWT = signJwt(privateKey, header, jwtClaimsSet);

            Jwt jwt = new Jwt(signedJWT.serialize(), jwtClaimsSet.getIssueTime().toInstant(),
                    jwtClaimsSet.getExpirationTime().toInstant(), header.toJSONObject(),
                    jwtClaimsSet.getClaims());

            return Mono.just(jwt);
        } catch (Exception e) {
            LOG.error("Error generating the assertion", e);
            throw new RuntimeException(e.getMessage());
        }
    }

    private SignedJWT signJwt(PrivateKey privateKey, JWSHeader header, JWTClaimsSet jwtClaimsSet) throws JOSEException {
        RSASSASigner signer = new RSASSASigner(privateKey);
        SignedJWT signedJwt = new SignedJWT(header, jwtClaimsSet);
        signedJwt.sign(signer);
        return signedJwt;
    }
}
