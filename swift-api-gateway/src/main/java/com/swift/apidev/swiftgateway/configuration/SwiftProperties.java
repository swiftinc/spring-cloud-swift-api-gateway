package com.swift.apidev.swiftgateway.configuration;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import jakarta.annotation.PostConstruct;
import jakarta.validation.constraints.NotBlank;

/**
 * Configuration properties for Swift channel certificates.
 */
@Configuration
@ConfigurationProperties(prefix = "swift")
public class SwiftProperties {

    private static final Logger LOG = LoggerFactory.getLogger(SwiftProperties.class);

    private final ResourceLoader resourceLoader;

    private final Map<String, ChannelCertificate> channelCertificates = new HashMap<>();

    public SwiftProperties(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    public Map<String, ChannelCertificate> getChannelCertificates() {
        return channelCertificates;
    }

    @PostConstruct
    public void init() {
        LOG.info("Initializing channel certificates");
        channelCertificates.forEach((key, channelCertificate) -> {
            try {
                LOG.info("Initializing channel certificate: {}", key);
                channelCertificate.init(resourceLoader);
            } catch (Exception e) {
                throw new RuntimeException("Failed to initialize channel certificate: " +
                        key, e);
            }
        });
    }

    public static class ChannelCertificate {
        @NotBlank
        private String location;

        @NotBlank
        private char[] password;

        @NotBlank
        private String alias;

        @NotBlank
        private char[] keyPassword;

        private X509Certificate x509Certificate;

        private PrivateKey privateKey;

        public void init(ResourceLoader resourceLoader) throws Exception {
            Resource resource = resourceLoader.getResource(location);
            if (!resource.exists()) {
                throw new IllegalArgumentException("Keystore not found: " + location);
            }

            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(resource.getInputStream(), password);
            this.x509Certificate = (X509Certificate) keyStore.getCertificate(alias);
            if (this.x509Certificate == null) {
                throw new IllegalArgumentException(
                        "Certificate with alias " + alias + " not found in keystore " + location);
            }

            this.privateKey = (PrivateKey) keyStore.getKey(alias, keyPassword);
        }

        public X509Certificate x509Certificate() {
            return x509Certificate;
        }

        public PrivateKey privateKey() {
            return privateKey;
        }

        public void setLocation(String location) {
            this.location = location;
        }

        public void setAlias(String alias) {
            this.alias = alias;
        }

        public void setKeyPassword(char[] keyPassword) {
            this.keyPassword = keyPassword;
        }

        public void setPassword(char[] password) {
            this.password = password;
        }
    }
}
