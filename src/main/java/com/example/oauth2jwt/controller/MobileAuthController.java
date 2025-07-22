package com.example.oauth2jwt.controller;

import com.example.oauth2jwt.provider.JwtTokenProvider;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/mobile/auth")
@RequiredArgsConstructor
public class MobileAuthController {

    private final JwtTokenProvider jwtTokenProvider;

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

    // 기존 중복 코드 (JwtAuthenticationFilter와 동일한 로직이 중복되어 제거됨)
    // @GetMapping("/verify")
    // public ResponseEntity<?> verifyToken(HttpServletRequest request) {
    //     try {
    //         // 프로세스 1: Authorization 헤더에서 토큰 추출 (인가) - JwtAuthenticationFilter에서 이미 처리됨
    //         String token = getJwtFromHeader(request);
    //         
    //         if (token != null && jwtTokenProvider.validateToken(token)) { // 중복된 토큰 검증
    //             // 프로세스 2: 토큰에서 사용자 이메일 추출 (인가) - 중복된 이메일 추출
    //             String email = jwtTokenProvider.getEmailFromToken(token);
    //             log.info("모바일 토큰 검증 성공: {}", email);
    //             
    //             // 프로세스 3: 인증 성공 응답 반환 (인가)
    //             return ResponseEntity.ok().body(new VerifyResponse(true, email, "토큰이 유효합니다."));
    //         } else {
    //             log.warn("모바일 토큰 검증 실패");
    //             return ResponseEntity.status(401).body(new VerifyResponse(false, null, "토큰이 유효하지 않습니다."));
    //         }
    //     } catch (Exception e) {
    //         log.error("모바일 토큰 검증 중 오류 발생", e);
    //         return ResponseEntity.status(500).body(new VerifyResponse(false, null, "토큰 검증 중 오류가 발생했습니다."));
    //     }
    // }

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