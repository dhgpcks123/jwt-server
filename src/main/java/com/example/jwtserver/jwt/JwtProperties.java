package com.example.jwtserver.jwt;

public interface JwtProperties {
    String SECRET = "cos";
    Integer EXPIRATION_TIME = 60000 * 10;
    String TOKEN_PREFIX = "Bearer ";
    String HEADER_STRING = "Authorization";
}
