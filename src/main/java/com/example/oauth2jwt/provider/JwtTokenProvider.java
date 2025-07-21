package com.example.oauth2jwt.provider;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Slf4j
@Component
public class JwtTokenProvider {

    private final SecretKey key;
    private final int jwtExpirationInMs;
    private final int refreshExpirationInMs;

    public JwtTokenProvider(@Value("${jwt.secret}") String jwtSecret,
                   @Value("${jwt.expiration}") int jwtExpirationInMs,
                   @Value("${jwt.refresh-expiration}") int refreshExpirationInMs) {
        this.key = Keys.hmacShaKeyFor(jwtSecret.getBytes());
        this.jwtExpirationInMs = jwtExpirationInMs;
        this.refreshExpirationInMs = refreshExpirationInMs;
    }

    /**
     * Authentication 객체로부터 Access Token 생성
     * 
     * 프로세스 흐름:
     * 이전: Spring Security에서 Authentication 객체 생성 완료 (인증)
     * 현재: 사용자 이메일 추출 -> JWT 클레임 설정 -> 디지털 서명 -> 토큰 생성 (인증)
     * 이후: 생성된 토큰을 HTTP-Only 쿠키로 설정하여 클라이언트에 전달 (인증)
     */
    public String generateToken(Authentication authentication) {
        String email = authentication.getName();
        Date expiryDate = new Date(System.currentTimeMillis() + jwtExpirationInMs);

        return Jwts.builder()
                .subject(email)
                .issuedAt(new Date())
                .expiration(expiryDate)
                .signWith(key)
                .compact();
    }

    /**
     * 이메일로부터 Access Token 생성 (오버로드 메서드)
     * 
     * 프로세스 흐름:
     * 이전: OAuth2AuthenticationSuccessHandler에서 사용자 정보 저장 완료 (인증)
     * 현재: 이메일을 subject로 설정 -> JWT 클레임 설정 -> 디지털 서명 -> Access Token 생성 (인증)
     * 이후: Refresh Token 생성 프로세스 진행 (인증)
     */
    public String generateToken(String email) {
        Date expiryDate = new Date(System.currentTimeMillis() + jwtExpirationInMs);

        return Jwts.builder()
                .subject(email)
                .issuedAt(new Date())
                .expiration(expiryDate)
                .signWith(key)
                .compact();
    }

    /**
     * 이메일로부터 Refresh Token 생성
     * 
     * 프로세스 흐름:
     * 이전: Access Token 생성 완료 (인증)
     * 현재: 이메일을 subject로 설정 -> 긴 만료시간(7일) 설정 -> 디지털 서명 -> Refresh Token 생성 (인증)
     * 이후: 두 토큰을 HTTP-Only 쿠키로 설정하여 클라이언트에 전달 (인증)
     */
    public String generateRefreshToken(String email) {
        Date expiryDate = new Date(System.currentTimeMillis() + refreshExpirationInMs);

        return Jwts.builder()
                .subject(email)
                .issuedAt(new Date())
                .expiration(expiryDate)
                .signWith(key)
                .compact();
    }

    /**
     * JWT 토큰에서 이메일 추출
     * 
     * 프로세스 흐름:
     * 이전: JwtAuthenticationFilter에서 토큰 유효성 검증 완료 (인가)
     * 현재: JWT 토큰 파싱 -> 디지털 서명 검증 -> 클레임에서 subject(이메일) 추출 (인가)
     * 이후: 추출된 이메일로 UserDetailsService에서 사용자 정보 로드 (인가)
     */
    public String getEmailFromToken(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return claims.getSubject();
    }

    /**
     * JWT 토큰 유효성 검증
     * 
     * 프로세스 흐름:
     * 이전: JwtAuthenticationFilter에서 쿠키 또는 Authorization 헤더에서 토큰 추출 완료 (인가)
     * 현재: JWT 파싱 -> 디지털 서명 검증 -> 만료 시간 확인 -> 토큰 유효성 반환 (인가)
     * 이후: 유효한 경우 사용자 이메일 추출 및 인증 객체 생성 (인가)
     */
    public boolean validateToken(String authToken) {
        try {
            Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(authToken);
            return true;
        } catch (MalformedJwtException ex) {
            log.error("Invalid JWT token");
        } catch (ExpiredJwtException ex) {
            log.error("Expired JWT token");
        } catch (UnsupportedJwtException ex) {
            log.error("Unsupported JWT token");
        } catch (IllegalArgumentException ex) {
            log.error("JWT claims string is empty");
        }
        return false;
    }

    /**
     * JWT 토큰에서 만료 날짜 추출
     * 
     * 프로세스: 토큰 만료 시간 확인을 위한 보조 메서드 (인가)
     */
    public Date getExpirationDateFromToken(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return claims.getExpiration();
    }

    /**
     * JWT 토큰 만료 여부 확인
     * 
     * 프로세스: 토큰 만료 여부 확인을 위한 보조 메서드 (인가)
     */
    public boolean isTokenExpired(String token) {
        Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }
}