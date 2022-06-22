package com.ron2ader.issuetracker.auth.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtProvider {

    private final JwtProperties jwtProperties;
    private final Key secretKey;
    private final JwtParser jwtParser;

    public JwtProvider(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
        this.secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        this.jwtParser = Jwts.parserBuilder()
                .requireIssuer(jwtProperties.getIssuer())
                .setSigningKey(secretKey)
                .build();
    }

    public String generateAccessToken(String userId) {
        return generateToken(userId, jwtProperties.getAccessSubject(), jwtProperties.getAccessExpirationTime());
    }

    public String generateRefreshToken(String userId) {
        return generateToken(userId, jwtProperties.getRefreshSubject(), jwtProperties.getRefreshExpirationTime());
    }

    public String getPayload(String token) {
        return jwtParser.parseClaimsJws(token).getBody().getAudience();
    }

    public boolean validateToken(String token) {
        try {
            Jws<Claims> claims = jwtParser.parseClaimsJws(token);
            return !claims.getBody().getExpiration().before(new Date());
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    private String generateToken(String userId, String subject, long expirationTime) {
        Date now = new Date();
        Date expiration = new Date(now.getTime() + expirationTime);
        return Jwts.builder()
                .setSubject(subject)
                .setIssuer(jwtProperties.getIssuer())
                .setAudience(userId)
                .setIssuedAt(now)
                .setExpiration(expiration)
                .signWith(secretKey)
                .compact();
    }

}
