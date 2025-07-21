package com.example.oauth2jwt.filter;

import com.example.oauth2jwt.service.UserService;
import com.example.oauth2jwt.provider.JwtTokenProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final UserDetailsService userDetailsService;

    /**
     * 모든 HTTP 요청에 대해 JWT 토큰 검증 및 인증 처리를 수행하는 필터
     * 
     * 프로세스 흐름:
     * 이전: 클라이언트에서 JWT 토큰이 포함된 API 요청 또는 쿠키와 함께 요청 (인가)
     * 현재: 쿠키/헤더에서 토큰 추출 -> 토큰 유효성 검증 -> 사용자 정보 로드 -> 인증 객체 생성 -> SecurityContext에 설정 (인가)
     * 이후: Spring Security에서 인증된 사용자로 인식하여 리소스 접근 여부 결정 (인가)
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            // 프로세스 1: 요청에서 JWT 토큰 추출 (인가)
            String jwt = getJwtFromRequest(request);

            if (StringUtils.hasText(jwt) && jwtTokenProvider.validateToken(jwt)) { //유효성 검증
                // 프로세스 2: 토큰에서 사용자 이메일 추출 (인가)
                String email = jwtTokenProvider.getEmailFromToken(jwt);
                
                // 프로세스 3: 사용자 상세 정보 로드 (인가)
                UserDetails userDetails = userDetailsService.loadUserByUsername(email);
                
                // 프로세스 4: Spring Security 인증 객체 생성 (인가)
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                
                // 프로세스 5: SecurityContext에 인증 정보 설정 (인가)
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception ex) {
            log.error("Could not set user authentication in security context", ex);
        }
        
        filterChain.doFilter(request, response);
    }

    /**
     * HTTP 요청에서 JWT 토큰 추출 (헤더 우선, 쿠키 보조)
     * 
     * 프로세스 흐름:
     * 이전: doFilterInternal에서 호출 (인가)
     * 현재: Authorization 헤더에서 토큰 추출 시도 -> 실패시 HTTP-Only 쿠키에서 추출 시도 (인가)
     * 이후: 추출된 토큰의 유효성 검증 진행 (인가)
     */
    private String getJwtFromRequest(HttpServletRequest request) {
        // 1순위: Authorization 헤더에서 토큰 추출 (모바일 친화적 방식)
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        
        // 2순위: HTTP-Only 쿠키에서 토큰 추출 (웹 브라우저 호환성 유지)
        String jwtFromCookie = getJwtFromCookie(request);
        if (StringUtils.hasText(jwtFromCookie)) {
            return jwtFromCookie;
        }
        
        return null;
    }
    
    /**
     * HTTP-Only 쿠키에서 JWT 토큰 추출
     * 
     * 프로세스: 보안상 안전한 HTTP-Only 쿠키에서 accessToken 추출 (인가)
     * XSS 공격에 대한 방어 효과 - JavaScript로 접근 불가
     */
    private String getJwtFromCookie(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("accessToken".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}