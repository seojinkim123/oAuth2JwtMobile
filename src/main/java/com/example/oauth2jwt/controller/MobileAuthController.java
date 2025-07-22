package com.example.oauth2jwt.controller;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;


@Slf4j
@RestController
@RequestMapping("/api/mobile/auth")
@RequiredArgsConstructor
public class MobileAuthController {


    /**
     * 모바일용 JWT 토큰 유효성 검증 API 엔드포인트
     * 
     * 프로세스 흐름 (개선됨):
     * 이전: 모바일 앱에서 Authorization 헤더로 토큰을 포함하여 API 호출 (인가)
     * 현재: JwtAuthenticationFilter에서 이미 토큰 검증 완료 -> SecurityContext에서 인증 정보 추출 -> 결과 반환 (인가)
     * 이후: 모바일 앱에서 인증 상태에 따른 UI 처리 (인가)
     */
    @GetMapping("/verify")
    public ResponseEntity<?> verifyToken(Authentication authentication) {
        try {
            // JwtAuthenticationFilter에서 이미 토큰 검증이 완료되어 SecurityContext에 인증 정보가 설정됨
            if (authentication != null && authentication.isAuthenticated()) {
                String email = authentication.getName(); // 이미 필터에서 검증된 사용자 이메일
                log.info("모바일 토큰 검증 성공: {}", email);
                
                return ResponseEntity.ok().body(new VerifyResponse(true, email, "토큰이 유효합니다."));
            } else {
                log.warn("모바일 토큰 검증 실패 - 인증 정보 없음");
                return ResponseEntity.status(401).body(new VerifyResponse(false, null, "토큰이 유효하지 않습니다."));
            }
        } catch (Exception e) {
            log.error("모바일 토큰 검증 중 오류 발생", e);
            return ResponseEntity.status(500).body(new VerifyResponse(false, null, "토큰 검증 중 오류가 발생했습니다."));
        }
    }


    /**
     * 모바일용 로그아웃 API - 토큰 무효화 처리
     * 
     * 프로세스 흐름:
     * 이전: 모바일 앱에서 로그아웃 버튼 클릭 또는 자동 로그아웃 로직 실행 (인증/인가)
     * 현재: 토큰 무효화 처리 (향후 블랙리스트 구현 가능) -> 로그아웃 성공 응답 (인증/인가)
     * 이후: 모바일 앱에서 로컬 저장소 토큰 삭제 및 로그인 화면으로 이동 (인증/인가)
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        try {
            // 프로세스 1: Authorization 헤더에서 토큰 추출 (인증/인가)
            String token = getJwtFromHeader(request);
            
            if (token != null) {
                // TODO: 향후 토큰 블랙리스트 기능 구현 시 여기에 추가
                // 현재는 클라이언트 측에서 토큰 삭제로 처리
                log.info("모바일 로그아웃 요청 처리 완료");
            }
            
            return ResponseEntity.ok().body(new LogoutResponse(true, "로그아웃이 완료되었습니다."));
            
        } catch (Exception e) {
            log.error("모바일 로그아웃 중 오류 발생", e);
            return ResponseEntity.status(500).body(new LogoutResponse(false, "로그아웃 중 오류가 발생했습니다."));
        }
    }

    /**
     * Authorization 헤더에서 JWT 토큰 추출
     * 
     * 프로세스: Authorization 헤더에서 "Bearer " 접두사를 제거하고 토큰 추출 (인가)
     */
    private String getJwtFromHeader(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
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

/*
*
* 🚀 실제 동작 흐름

  인증된 요청의 경우:

  1. HTTP 요청 도착
  2. JwtAuthenticationFilter 실행
     - JWT 토큰 검증 ✓
     - UserDetails 생성 ✓
     - Authentication 객체 생성 ✓
     - SecurityContext.setAuthentication(auth) ✓

  3. Controller 메서드 호출
     - Spring MVC: "Authentication 파라미터 있네?"
     - Spring MVC: "SecurityContext에서 가져다 줄게!"
     - verifyToken(authentication) 호출

  4. authentication != null &&
  authentication.isAuthenticated() = true ✓

  비인증 요청의 경우:

  1. HTTP 요청 도착
  2. JwtAuthenticationFilter 실행
     - 토큰 없음 or 잘못된 토큰
     - SecurityContext에 아무것도 설정 안 함

  3. Controller 메서드 호출
     - Spring MVC: "SecurityContext가 비어있네?"
     - verifyToken(null) 호출

  4. authentication == null = true → 401 응답

  🎯 다른 방법들과 비교

*
* */