package com.simpleoauth2server.Config.Jwt;



import com.simpleoauth2server.GlobeAdvice.Exceptions.*;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JWTProvider {
    @Value("${app.jwt-secret}")
    private String secret_key;
    @Value("${app.jwt-expiration-milliseconds}")
    private Long accessTokenExpirationMillis;

    @Value("${app.jwt-refresh-token.expiration-days}")
    private Long refreshTokenExpirationDays;


    public String generateRefreshToken(Authentication authentication) {
        String userName = authentication.getName();

        // Set expiration to 1 year
        long oneYearInMillis = refreshTokenExpirationDays * 24 * 60 * 60 * 1000; // 365 days in milliseconds
        Date expirationDate = new Date(new Date().getTime() + oneYearInMillis);

        return Jwts.builder()
                .setSubject(userName)
                .setIssuedAt(new Date())
                .setExpiration(expirationDate)
                .claim("tokenType", "REFRESH")
                .signWith(the_key())
                .compact();
    }


    public String getUserName(String token) {

        Claims claims = Jwts.parserBuilder()
                .setSigningKey(the_key())
                .build()
                .parseClaimsJws(token)
                .getBody();

        return claims.getSubject();
    }

    public String generateAccessToken(Authentication authentication) {
        String userName = authentication.getName();

        Date currentDate = new Date();
        Date expirationDate = new Date(currentDate.getTime() + accessTokenExpirationMillis);

        return Jwts.builder()
                .setSubject(userName)
                .setIssuedAt(currentDate)
                .setExpiration(expirationDate)
                .signWith(the_key())
                .claim("tokenType", "ACCESS")
                .compact();
    }


    public boolean validToken(String token, String expectedTokenType) throws Exception {

        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(the_key())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            String tokenType = claims.get("tokenType", String.class);
            if (!expectedTokenType.equals(tokenType)) {
                throw new TokenInvalidSignatureException("Invalid token");
            }
            return true;
        } catch (MalformedJwtException malformedJwtException) {
            throw new TokenInvalidException("Invalid token");
        } catch (ExpiredJwtException expiredJwtException) {
            throw new TokenExpiredException("Token expired");
        } catch (UnsupportedJwtException unsupportedJwtException) {
            throw new TokenUnsupportedException("Unsupported token");
        } catch (IllegalArgumentException illegalArgumentException) {
            throw new TokenEmptyException("Empty token");
        }catch (SignatureException signatureException) {
            throw new TokenInvalidSignatureException("Invalid JWT signature");
        }

    }

    private Key the_key() {
        return Keys.hmacShaKeyFor(
                Decoders.BASE64.decode(secret_key)
        );
    }
}
