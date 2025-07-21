package com.example.oauth2jwt.service;

import com.example.oauth2jwt.dto.UserDto;
import com.example.oauth2jwt.entity.User;
import com.example.oauth2jwt.repository.UserRepository;
import com.example.oauth2jwt.provider.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class AuthService {

    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;

    /**
     * Refresh Token을 사용하여 새로운 Access Token과 Refresh Token 발급
     * 
     * 프로세스 흐름:
     * 이전: Access Token 만료 또는 만료 예정시 프론트엔드에서 호출 (인증)
     * 현재: Refresh Token 유효성 검증 -> 사용자 이메일 추출 -> 사용자 존재 확인 -> 새 토큰들 발급 (인증)
     * 이후: 새로 발급된 토큰들을 쿠키로 설정하여 클라이언트에 전달 (인증)
     */
    public Map<String, String> refreshToken(String refreshToken) {
        Map<String, String> result = new HashMap<>();
        
        try {
            // 프로세스 1: Refresh Token 유효성 검증 (인증)
            if (jwtTokenProvider.validateToken(refreshToken)) {
                // 프로세스 2: 토큰에서 사용자 이메일 추출 (인증)
                String email = jwtTokenProvider.getEmailFromToken(refreshToken);
                
                // 프로세스 3: 데이터베이스에서 사용자 존재 확인 (인증)
                Optional<User> userOptional = userRepository.findByEmail(email);
                if (userOptional.isPresent()) {
                    // 프로세스 4: 새로운 Access Token과 Refresh Token 발급 (인증)
                    String newAccessToken = jwtTokenProvider.generateToken(email);
                    String newRefreshToken = jwtTokenProvider.generateRefreshToken(email);
                    
                    result.put("accessToken", newAccessToken);
                    result.put("refreshToken", newRefreshToken);
                    result.put("message", "토큰이 성공적으로 갱신되었습니다.");
                } else {
                    result.put("error", "사용자를 찾을 수 없습니다.");
                }
            } else {
                result.put("error", "유효하지 않은 리프레시 토큰입니다.");
            }
        } catch (Exception e) {
            log.error("토큰 갱신 중 오류 발생", e);
            result.put("error", "토큰 갱신 중 오류가 발생했습니다.");
        }
        
        return result;
    }

    /**
     * 현재 로그인한 사용자 정보 조회
     * 
     * 프로세스 흐름:
     * 이전: JwtAuthenticationFilter에서 SecurityContext에 인증 정보 설정 완료 (인가)
     * 현재: SecurityContext에서 Authentication 객체 추출 -> 인증 상태 확인 -> 사용자 이메일 추출 -> 데이터베이스에서 사용자 정보 조회 (인가)
     * 이후: 조회된 사용자 정보를 API 응답으로 반환 (인가)
     */
    public Optional<UserDto> getCurrentUser() {
        // 프로세스 1: SecurityContext에서 인증 객체 추출 (인가)
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        // 프로세스 2: 인증 상태 및 사용자 확인 (인가)
        if (authentication != null && authentication.isAuthenticated() && 
            !authentication.getName().equals("anonymousUser")) {
            
            // 프로세스 3: 사용자 이메일 추출 및 데이터베이스 조회 (인가)
            String email = authentication.getName();
            return userRepository.findByEmail(email).map(UserDto::from);
        }
        
        return Optional.empty();
    }

    /**
     * JWT 토큰 유효성 검사 래퍼 메서드
     * 
     * 프로세스: JwtTokenProvider의 validateToken 메서드를 호출하여 토큰 유효성 검사 (인가)
     */
    public boolean isTokenValid(String token) {
        return jwtTokenProvider.validateToken(token);
    }

    /**
     * JWT 토큰에서 이메일 추출 래퍼 메서드
     * 
     * 프로세스: JwtTokenProvider의 getEmailFromToken 메서드를 호출하여 토큰에서 이메일 추출 (인가)
     */
    public String getEmailFromToken(String token) {
        return jwtTokenProvider.getEmailFromToken(token);
    }
}