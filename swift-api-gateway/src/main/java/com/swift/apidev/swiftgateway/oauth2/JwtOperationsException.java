package com.swift.apidev.swiftgateway.oauth2;

public class JwtOperationsException extends RuntimeException {
    public JwtOperationsException(Throwable t) {
        super(t);
    }

    public JwtOperationsException(String message) {
        super(message);
    }
}