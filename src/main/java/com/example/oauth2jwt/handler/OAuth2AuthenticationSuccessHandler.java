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
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.io.PrintWriter;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;

    /**
     * OAuth2 로그인 성공 후 처리하는 핵심 메서드 (웹/모바일 분기처리)
     * 
     * 프로세스 흐름:
     * 이전: Google OAuth2 서버에서 인증 완료 후 Spring Security가 Authentication 객체 생성 (인증)
     * 현재: 클라이언트 타입 감지 -> OAuth2 사용자 정보 추출 -> 사용자 저장/업데이트 -> JWT 토큰 발급 -> 웹/모바일별 처리 (인증)
     * 이후: 웹/모바일에서 각각의 방식으로 토큰을 사용하여 API 요청 시 인증 (인가)
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, 
                                      HttpServletResponse response,
                                      Authentication authentication) throws IOException, ServletException {
        
        // 프로세스 1: 클라이언트 타입 감지 (인증)
        boolean isMobileClient = detectMobileClient(request);
        
        // 프로세스 2: OAuth2 사용자 정보 추출 (인증)
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        
        String email = extractEmail(oAuth2User);
        String name = extractName(oAuth2User);
        String picture = extractPicture(oAuth2User);
        String provider = "google"; // Google OAuth2만 우선 지원
        String providerId = extractProviderId(oAuth2User);
        
        // 디버깅용 로그 추가
        log.debug("OAuth2 사용자 정보 - 이메일: {}, 이름: {}, 프로필사진: {}", email, name, picture);
        
        // 프로세스 3: 사용자 정보 저장/업데이트 (인증)
        User user = saveOrUpdateUser(email, name, picture, provider, providerId);
        
        // 프로세스 4: JWT 토큰 발급 (인증)
        String token = jwtTokenProvider.generateToken(email);
        String refreshToken = jwtTokenProvider.generateRefreshToken(email);
        
        // 프로세스 5: 클라이언트 타입별 처리 분기 (인증)
        if (isMobileClient) {
            handleMobileSuccess(request, response, email, token, refreshToken);
        } else {
            handleWebSuccess(request, response, email, token, refreshToken);
        }
    }

    /**
     * 웹 클라이언트 OAuth2 로그인 성공 처리
     * 
     * 프로세스: HTTP-Only 쿠키 설정 -> 브라우저 리다이렉트 (인증)
     */
    private void handleWebSuccess(HttpServletRequest request, HttpServletResponse response, 
                                String email, String token, String refreshToken) throws IOException {
        // HTTP-Only 쿠키로 토큰 설정 (XSS 공격 방지)
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
        
        // 프론트엔드로 리다이렉트
        String targetUrl = "http://localhost:3000/oauth2/redirect?success=true";
        
        log.info("Web OAuth2 login success for user: {}", email);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    /**
     * 모바일 클라이언트 OAuth2 로그인 성공 처리
     * 
     * 프로세스: JSON 토큰 응답 -> 딥링크 리다이렉트 (인증)
     */
    private void handleMobileSuccess(HttpServletRequest request, HttpServletResponse response, 
                                   String email, String token, String refreshToken) throws IOException {
        // JSON 응답으로 토큰 전달
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        
        String jsonResponse = String.format(
            "{\"success\": true, \"message\": \"로그인 성공\", \"accessToken\": \"%s\", \"refreshToken\": \"%s\", \"email\": \"%s\"}",
            token, refreshToken, email
        );
        
        PrintWriter writer = response.getWriter();
        writer.write(jsonResponse);
        writer.flush();
        
        log.info("Mobile OAuth2 login success for user: {}", email);
        
        // TODO: 향후 딥링크 리다이렉트 추가 (yourapp://oauth/callback?token=...)
        // 현재는 JSON 응답으로만 처리
    }

    /**
     * 모바일 클라이언트 감지
     * 
     * 프로세스: User-Agent 헤더 또는 요청 파라미터를 통해 모바일 클라이언트 여부 판단 (인증)
     */
    private boolean detectMobileClient(HttpServletRequest request) {
        // 방법 1: 요청 파라미터로 클라이언트 타입 구분
        String clientType = request.getParameter("client_type");
        if ("mobile".equals(clientType)) {
            return true;
        }
        
        // 방법 2: User-Agent 헤더로 모바일 감지
        String userAgent = request.getHeader("User-Agent");
        if (StringUtils.hasText(userAgent)) {
            userAgent = userAgent.toLowerCase();
            return userAgent.contains("mobile") || 
                   userAgent.contains("android") || 
                   userAgent.contains("iphone") || 
                   userAgent.contains("ipad");
        }
        
        // 기본값: 웹 클라이언트로 간주
        return false;
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

/*
*  🔄 OAuth2 로그인 플로우

  Step 1: 사용자가 로그인 버튼 클릭

  const handleGoogleLogin = () => {
      window.location.href =
  'http://localhost:8080/oauth2/authorization/google';
  };

  Step 2: Spring Security가 Google로 리다이렉트

  브라우저 이동:
  http://localhost:8080/oauth2/authorization/google
  ↓
  https://accounts.google.com/o/oauth2/auth?
    client_id=105264979588-ohrpkkeqmerkt6b01av0sv82ohqlk
  u04.apps.googleusercontent.com
    &redirect_uri=http://localhost:8080/login/oauth2/cod
  e/google
    &response_type=code
    &scope=profile email

  Step 3: 사용자가 Google에서 로그인/동의

  Google 로그인 페이지에서:
  - 이메일/비밀번호 입력
  - "앱에 권한 허용하시겠습니까?" 동의

  Step 4: Google이 인가 코드와 함께 백엔드로 리다이렉트

  http://localhost:8080/login/oauth2/code/google?code=4/
  0AanQ...&state=xyz

  Step 5: Spring Security가 토큰 교환

  // Spring Security가 자동으로 처리:
  // 1. 인가 코드를 Google 토큰 서버로 전송
  // 2. Access Token 받음
  // 3. Google API로 사용자 정보 조회
  // 4. OAuth2AuthenticationSuccessHandler 실행

  Step 6: JWT 토큰 생성 후 프론트엔드로 리다이렉트

  // OAuth2AuthenticationSuccessHandler에서
  response.sendRedirect("http://localhost:3000/oauth2/ca
  llback?token=" + jwt);

* */