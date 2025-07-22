package com.example.oauth2jwt.controller;

import com.example.oauth2jwt.dto.UserDto;
import com.example.oauth2jwt.service.AuthService;
import com.example.oauth2jwt.provider.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final JwtTokenProvider jwtTokenProvider;

    /**
     * Refresh Token을 사용하여 새로운 Access Token과 Refresh Token 발급 (범용 API)
     * 
     * 프로세스 흐름:
     * 이전: Access Token 만료 또는 만료 예정시 웹/모바일에서 JSON으로 호출 (인증)
     * 현재: Refresh Token 유효성 검증 -> 새 토큰들 발급 -> JSON 응답 (인증)
     * 이후: 클라이언트에서 새 토큰을 저장하여 계속 사용 (인증)
     */
    @PostMapping("/refresh")
    public ResponseEntity<Map<String, String>> refreshToken(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");
        
        if (refreshToken == null || refreshToken.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "리프레시 토큰이 필요합니다."));
        }
        
        Map<String, String> result = authService.refreshToken(refreshToken);
        
        if (result.containsKey("error")) {
            return ResponseEntity.badRequest().body(result);
        }
        
        return ResponseEntity.ok(result);
    }

    /**
     * JWT 토큰 유효성 검증 (범용 API)
     * 
     * 프로세스 흐름:
     * 이전: 웹/모바일에서 토큰 상태 확인을 위해 JSON으로 호출 (인가)
     * 현재: 토큰 유효성 검증 -> 검증 결과 JSON 응답 (인가)
     * 이후: 클라이언트에서 토큰 상태에 따른 처리 (인가)
     */
    @PostMapping("/validate")
    public ResponseEntity<Map<String, Object>> validateToken(@RequestBody Map<String, String> request) {
        String token = request.get("token");
        
        if (token == null || token.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "토큰이 필요합니다."));
        }
        
        boolean isValid = jwtTokenProvider.validateToken(token);
        Map<String, Object> result = Map.of(
                "valid", isValid,
                "message", isValid ? "유효한 토큰입니다." : "유효하지 않은 토큰입니다."
        );
        
        return ResponseEntity.ok(result);
    }

    /**
     * 현재 로그인한 사용자 정보 조회 (범용 API)
     * 
     * 프로세스 흐름:
     * 이전: JWT 필터에서 SecurityContext에 인증 정보 설정 완료 (인가)
     * 현재: SecurityContext에서 사용자 정보 추출 -> 사용자 데이터 조회 -> JSON 응답 (인가)
     * 이후: 클라이언트에서 사용자 정보를 활용한 UI 처리 (인가)
     */
    @GetMapping("/me")
    public ResponseEntity<UserDto> getCurrentUser() {
        return authService.getCurrentUser()
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }
}