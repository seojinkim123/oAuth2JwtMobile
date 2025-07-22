package com.example.oauth2jwt.controller;

import com.example.oauth2jwt.provider.JwtTokenProvider;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/web/auth")
@RequiredArgsConstructor
public class WebAuthController {

    private final JwtTokenProvider jwtTokenProvider;

    /**
     * JWT 토큰 유효성 검증 API 엔드포인트
     * 
     * 프로세스 흐름 (개선됨):
     * 이전: 프론트엔드에서 인증 상태 확인을 위한 API 호출 (인가)
     * 현재: JwtAuthenticationFilter에서 이미 토큰 검증 완료 -> SecurityContext에서 인증 정보 추출 -> 결과 반환 (인가)
     * 이후: 프론트엔드에서 인증 상태에 따른 UI 처리 (인가)
     */
    @GetMapping("/verify")
    public ResponseEntity<?> verifyToken(Authentication authentication) {
        try {
            // JwtAuthenticationFilter에서 이미 토큰 검증이 완료되어 SecurityContext에 인증 정보가 설정됨
            if (authentication != null && authentication.isAuthenticated()) {
                String email = authentication.getName(); // 이미 필터에서 검증된 사용자 이메일
                log.info("토큰 검증 성공: {}", email);
                
                return ResponseEntity.ok().body(new VerifyResponse(true, email, "토큰이 유효합니다."));
            } else {
                log.warn("토큰 검증 실패 - 인증 정보 없음");
                return ResponseEntity.status(401).body(new VerifyResponse(false, null, "토큰이 유효하지 않습니다."));
            }
        } catch (Exception e) {
            log.error("토큰 검증 중 오류 발생", e);
            return ResponseEntity.status(500).body(new VerifyResponse(false, null, "토큰 검증 중 오류가 발생했습니다."));
        }
    }

    /**
     * 로그아웃 API - HTTP-Only 쿠키 삭제
     * 
     * 프로세스 흐름:
     * 이전: 프론트엔드에서 로그아웃 버튼 클릭 또는 자동 로그아웃 로직 실행 (인증/인가)
     * 현재: accessToken 쿠키 만료 설정 -> refreshToken 쿠키 만료 설정 -> 로그아웃 성공 응답 (인증/인가)
     * 이후: 프론트엔드에서 로그인 페이지로 리다이렉트 (인증/인가)
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletResponse response) {
        try {
            // 프로세스 1: accessToken 쿠키 만료 설정으로 삭제 (인증/인가)
            Cookie accessCookie = new Cookie("accessToken", null);
            accessCookie.setHttpOnly(true);
            accessCookie.setSecure(false); // HTTPS 환경에서는 true로 설정
            accessCookie.setPath("/");
            accessCookie.setMaxAge(0); // 즉시 만료
            
            // 프로세스 2: refreshToken 쿠키 만료 설정으로 삭제 (인증/인가)
            Cookie refreshCookie = new Cookie("refreshToken", null);
            refreshCookie.setHttpOnly(true);
            refreshCookie.setSecure(false); // HTTPS 환경에서는 true로 설정
            refreshCookie.setPath("/");
            refreshCookie.setMaxAge(0); // 즉시 만료
            
            response.addCookie(accessCookie);
            response.addCookie(refreshCookie);
            
            log.info("로그아웃 성공 - 쿠키 삭제 완료");
            return ResponseEntity.ok().body(new LogoutResponse(true, "로그아웃이 완료되었습니다."));
            
        } catch (Exception e) {
            log.error("로그아웃 중 오류 발생", e);
            return ResponseEntity.status(500).body(new LogoutResponse(false, "로그아웃 중 오류가 발생했습니다."));
        }
    }

    /**
     * 디버깅용 토큰 정보 조회 API (개발환경 전용)
     * 
     * 프로세스: 개발 중 토큰 상태 확인을 위한 디버깅 도구 (인가)
     * 운영환경에서는 보안상 비활성화
     */
    @GetMapping("/debug/token")
    @org.springframework.context.annotation.Profile("dev")
    public ResponseEntity<?> debugToken(HttpServletRequest request) {
        try {
            String accessToken = getJwtFromCookie(request, "accessToken");
            String refreshToken = getJwtFromCookie(request, "refreshToken");
            
            if (accessToken != null) {
                String email = jwtTokenProvider.getEmailFromToken(accessToken);
                boolean isValid = jwtTokenProvider.validateToken(accessToken);
                
                return ResponseEntity.ok().body(Map.of(
                    "accessToken", accessToken,
                    "refreshToken", refreshToken != null ? refreshToken : "없음",
                    "email", email,
                    "valid", isValid,
                    "message", "토큰 정보 조회 성공"
                ));
            } else {
                return ResponseEntity.ok().body(Map.of("message", "토큰이 없습니다."));
            }
        } catch (Exception e) {
            log.error("토큰 디버깅 중 오류 발생", e);
            return ResponseEntity.status(500).body(Map.of("error", "토큰 디버깅 중 오류가 발생했습니다."));
        }
    }

    /**
     * 쿠키에서 JWT 토큰 추출 (기본: accessToken)
     * 
     * 프로세스: HTTP-Only 쿠키에서 accessToken 추출하는 보조 메서드 (인가)
     */
    private String getJwtFromCookie(HttpServletRequest request) {
        return getJwtFromCookie(request, "accessToken");
    }
    
    /**
     * 쿠키에서 특정 이름의 JWT 토큰 추출
     * 
     * 프로세스: 지정된 이름의 쿠키에서 토큰 값 추출하는 보조 메서드 (인가)
     * accessToken 또는 refreshToken 추출 가능
     */
    private String getJwtFromCookie(HttpServletRequest request, String cookieName) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (cookieName.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    // 응답 DTO 클래스들
    public static class VerifyResponse {
        public boolean valid;
        public String email;
        public String message;

        public VerifyResponse(boolean valid, String email, String message) {
            this.valid = valid;
            this.email = email;
            this.message = message;
        }
    }

    public static class LogoutResponse {
        public boolean success;
        public String message;

        public LogoutResponse(boolean success, String message) {
            this.success = success;
            this.message = message;
        }
    }
}