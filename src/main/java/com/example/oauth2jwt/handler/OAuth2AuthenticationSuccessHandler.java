package com.example.oauth2jwt.handler;

import com.example.oauth2jwt.entity.Role;
import com.example.oauth2jwt.entity.User;
import com.example.oauth2jwt.repository.UserRepository;
import com.example.oauth2jwt.provider.JwtTokenProvider;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;

    /**
     * OAuth2 로그인 성공 후 처리하는 핵심 메서드
     * 
     * 프로세스 흐름:
     * 이전: Google OAuth2 서버에서 인증 완료 후 Spring Security가 Authentication 객체 생성 (인증)
     [ 자세히 : 구글에서 Authorization Code와 함께 브라우저를 우리 서버로 리다이렉트 →
                   Spring Security가 자동으로 (Code→Access Token 교환, 사용자 정보 조회, OAuth2User 객체 생성) 처리 후 호출]

     * 현재: OAuth2 사용자 정보 추출 -> 사용자 저장/업데이트 -> JWT 토큰 발급 -> 쿠키 설정 -> 프론트엔드로 리다이렉트 (인증)
     * 이후: 프론트엔드에서 쿠키의 JWT 토큰을 사용하여 API 요청 시 인증 (인가)
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, 
                                      HttpServletResponse response,
                                      Authentication authentication) throws IOException, ServletException {
        
        // 프로세스 1: OAuth2 사용자 정보 추출 (인증)
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        
        String email = extractEmail(oAuth2User);
        String name = extractName(oAuth2User);
        String picture = extractPicture(oAuth2User);
        String provider = "google"; // Google OAuth2만 우선 지원
        String providerId = extractProviderId(oAuth2User);
        
        // 프로세스 2: 사용자 정보 저장/업데이트 (인증)
        User user = saveOrUpdateUser(email, name, picture, provider, providerId);
        
        // 프로세스 3: JWT 토큰 발급 (인증)
        String token = jwtTokenProvider.generateToken(email);
        String refreshToken = jwtTokenProvider.generateRefreshToken(email);
        
        // 프로세스 4: HTTP-Only 쿠키로 토큰 설정 (인증)
        // XSS 공격 방지를 위해 JavaScript에서 접근 불가능한 HttpOnly 쿠키 사용
        Cookie accessCookie = new Cookie("accessToken", token);
        accessCookie.setHttpOnly(true);
        accessCookie.setSecure(false); // HTTPS 환경에서는 true로 설정
        accessCookie.setPath("/");
        accessCookie.setMaxAge(3600); // 1시간
        
        Cookie refreshCookie = new Cookie("refreshToken", refreshToken);
        refreshCookie.setHttpOnly(true);
        refreshCookie.setSecure(false); // HTTPS 환경에서는 true로 설정
        refreshCookie.setPath("/");
        refreshCookie.setMaxAge(604800); // 7일
        
        response.addCookie(accessCookie);
        response.addCookie(refreshCookie);
        
        // 프로세스 5: 프론트엔드로 리다이렉트 (인증)
        // 토큰은 쿠키에 저장되므로 URL에 노출하지 않아 보안상 안전
        String targetUrl = "http://localhost:3000/oauth2/redirect?success=true";
        
        log.info("OAuth2 login success for user: {}", email);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    /**
     * OAuth2 로그인 사용자 정보를 데이터베이스에 저장하거나 업데이트
     * 
     * 프로세스 흐름:
     * 이전: onAuthenticationSuccess에서 OAuth2 사용자 정보 추출 완료 (인증)
     * 현재: 이메일로 기존 사용자 조회 -> 존재시 정보 업데이트, 미존재시 신규 사용자 생성 -> DB 저장 (인증)
     * 이후: JWT 토큰 생성 프로세스 진행 (인증)
     */
    private User saveOrUpdateUser(String email, String name, String picture, String provider, String providerId) {
        User user = userRepository.findByEmail(email)
                .map(existingUser -> existingUser.update(name, picture))
                .orElse(User.builder()
                        .email(email)
                        .name(name)
                        .picture(picture)
                        .role(Role.USER)
                        .provider(provider)
                        .providerId(providerId)
                        .build());
        
        return userRepository.save(user);
    }

    /**
     * OAuth2 사용자 정보에서 이메일 추출
     * 
     * 프로세스: OAuth2 인증 완료 후 사용자 정보 추출 과정의 일부 (인증)
     */
    private String extractEmail(OAuth2User oAuth2User) {
        return oAuth2User.getAttribute("email");
    }

    /**
     * OAuth2 사용자 정보에서 이름 추출
     * 
     * 프로세스: OAuth2 인증 완료 후 사용자 정보 추출 과정의 일부 (인증)
     */
    private String extractName(OAuth2User oAuth2User) {
        return oAuth2User.getAttribute("name");
    }

    /**
     * OAuth2 사용자 정보에서 프로필 사진 URL 추출
     * 
     * 프로세스: OAuth2 인증 완료 후 사용자 정보 추출 과정의 일부 (인증)
     */
    private String extractPicture(OAuth2User oAuth2User) {
        return oAuth2User.getAttribute("picture");
    }

    /**
     * OAuth2 사용자 정보에서 제공자 고유 ID 추출
     * 
     * 프로세스: OAuth2 인증 완료 후 사용자 정보 추출 과정의 일부 (인증)
     * Google의 경우 'sub' 필드가 사용자의 고유 식별자
     */
    private String extractProviderId(OAuth2User oAuth2User) {
        return oAuth2User.getAttribute("sub");
    }
}