package com.example.oauth2jwt.config;

import com.example.oauth2jwt.filter.JwtAuthenticationFilter;
import com.example.oauth2jwt.handler.OAuth2AuthenticationSuccessHandler;
import com.example.oauth2jwt.provider.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfigurationSource;
import com.example.oauth2jwt.repository.UserRepository;

/**
 * Spring Security 설정 클래스
 * OAuth2와 JWT 기반 인증/인가 시스템의 핵심 보안 설정
 */
@Configuration // Spring Bean 설정 클래스임을 명시
@EnableWebSecurity // Spring Security 활성화
@RequiredArgsConstructor // final 필드에 대한 생성자 자동 생성
public class SecurityConfig {

    // OAuth2 로그인 성공 후 JWT 토큰 발급 및 쿠키 설정을 담당하는 핸들러
    private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
    // 사용자 정보 데이터베이스 조회를 위한 리포지토리
    private final UserRepository userRepository;
    // JWT 토큰 생성, 검증, 파싱을 담당하는 프로바이더
    private final JwtTokenProvider jwtTokenProvider;
    // CORS(Cross-Origin Resource Sharing) 설정 소스
    private final CorsConfigurationSource corsConfigurationSource;

    /**
     * JWT 인증 필터 빈 생성
     * 모든 HTTP 요청에서 JWT 토큰을 검증하고 인증 객체를 생성하는 필터
     */
    @Bean // Spring 컨테이너에서 관리하는 빈으로 등록
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        // JWT 토큰 프로바이더와 사용자 상세 정보 서비스를 주입하여 필터 생성
        return new JwtAuthenticationFilter(jwtTokenProvider, userDetailsService());
    }

    /**
     * Spring Security 필터 체인 설정
     * 
     * 동작 시점:
     * - 모든 HTTP 요청이 들어올 때마다 실행
     * - 클라이언트 요청 → Spring Security 필터 체인 → 컨트롤러 순서로 처리
     * - 각 필터는 순서대로 실행되며, 인증/인가 검사를 수행
     */
    @Bean // Spring 컨테이너에서 관리하는 빈으로 등록
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // CSRF(Cross-Site Request Forgery) 보호 비활성화
                // JWT 토큰 기반 인증에서는 CSRF 토큰이 불필요 (Stateless하므로)
                .csrf(csrf -> csrf.disable())
                
                // CORS(Cross-Origin Resource Sharing) 설정 활성화
                // 프론트엔드(React)와 백엔드(Spring) 간 다른 도메인 통신 허용
                .cors(cors -> cors.configurationSource(corsConfigurationSource))
                
                // 세션 관리 정책을 STATELESS로 설정
                // 서버에서 세션을 생성하지 않음 (JWT 토큰으로 상태 관리)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                
                // HTTP 요청에 대한 인가 규칙 설정 (⚠️ 이것은 '설정'이지 '실행 순서'가 아님!)
                // >>>>>실제로는 JWT 필터가 먼저 실행된 후, 이 인가 규칙이 적용됨<<<<<<<<
                .authorizeHttpRequests(authz -> authz
                        // 🔓 인증 없이 접근 가능한 경로들 (permitAll)
                        // 이 경로들은 JWT 필터를 거쳐도 인가 검사에서 통과시킴
                        // "/" - 홈페이지, "/h2-console/**" - H2 데이터베이스 콘솔
                        // "/api/hello" - 테스트용 API, "/oauth2/**" - OAuth2 로그인 경로
                        // "/login/**" - 로그인 관련 경로
                        // "/api/web/auth/logout", "/api/mobile/auth/logout" - 로그아웃은 인증 없이 허용
                        // "/api/web/auth/debug/**" - 개발환경 디버깅 API
                        .requestMatchers("/", "/h2-console/**", "/api/hello", "/oauth2/**", "/login/**", 
                                       "/api/web/auth/logout", "/api/mobile/auth/logout", "/api/web/auth/debug/**").permitAll()
                        
                        // 🔒 인증이 필요한 엔드포인트들 (보안 강화)
                        // "/api/web/auth/verify", "/api/mobile/auth/verify" - 토큰 검증은 인증된 사용자만
                        // "/api/auth/**" - 범용 인증 API (토큰 갱신, 사용자 정보 조회 등)
                        .requestMatchers("/api/web/auth/verify", "/api/mobile/auth/verify", "/api/auth/**").authenticated()
                        
                        // 🔒 위에서 정의한 경로 외의 모든 요청은 인증 필요
                        // JWT 필터에서 인증이 성공한 경우에만 접근 허용
                        // 범용 인증 API("/api/auth/**")는 인증이 필요함
                        .anyRequest().authenticated()
                )
                
                // OAuth2 로그인 설정
                .oauth2Login(oauth2 -> oauth2
                        // OAuth2 로그인 성공 시 실행할 핸들러 지정
                        // Google 로그인 완료 후 JWT 토큰 발급 및 쿠키 설정 처리
                        .successHandler(oAuth2AuthenticationSuccessHandler)
                )
                
                // 🔥 실제 필터 실행 순서 설정 (이것이 진짜 순서를 결정!)
                // JWT 인증 필터를 UsernamePasswordAuthenticationFilter 앞에 추가
                // 
                // 📋 실제 HTTP 요청 처리 순서:
                // 1️⃣ HTTP 요청 수신
                // 2️⃣ JWT 필터 실행 (토큰 검증 → 인증 객체 생성 → SecurityContext 설정)
                // 3️⃣ UsernamePasswordAuthenticationFilter  (⚠️ 필터 체인에는 있지만 실제로는 사용 안 함!)
                //    이유 1: 우리는 OAuth2 로그인만 사용 (username/password 로그인 안 함)
                //    이유 2: JWT 필터에서 이미 인증 완료되었으므로 스킵됨
                //    이유 3: 로그인 폼이 없으므로 처리할 요청이 없음
                // 4️⃣ Spring Security 인가 검사 (위에서 설정한 authorizeHttpRequests 규칙 적용)
                // 5️⃣ 인가 통과 시 컨트롤러로 요청 전달
                .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
                
                // HTTP 헤더 설정 - X-Frame-Options 비활성화
                // H2 콘솔 사용을 위해 프레임 옵션 해제 (개발 환경용)
                .headers(headers -> headers.frameOptions().disable());

        // 설정이 완료된 SecurityFilterChain 객체 반환
        return http.build();
    }

    /**
     * 사용자 상세 정보 서비스 빈 생성
     * 
     * 🔥 정확한 동작 시점:
     * 
     * 1️⃣ **JwtAuthenticationFilter에서 호출됨**
     *    - JWT 토큰에서 이메일 추출 후
     *    - 이 이메일로 userDetailsService.loadUserByUsername(email) 호출
     *    - 데이터베이스에서 사용자 정보 로드 → UserDetails 생성
     *    - Spring Security Authentication 객체 생성에 사용
     * 
     * 2️⃣ **사용되지 않는 경우**
     *    - OAuth2 로그인 중: OAuth2User 객체를 사용하므로 호출 안 됨
     *    - permitAll() 경로: 인증이 필요 없으므로 호출 안 됨
     *    - 잘못된 토큰: 토큰 검증 실패시 호출 안 됨
     * 
     * 3️⃣ **호출 경로**
     *    JwtAuthenticationFilter.doFilterInternal()
     *    → jwtTokenProvider.validateToken() (성공)
     *    → jwtTokenProvider.getEmailFromToken()
     *    → userDetailsService.loadUserByUsername(email) ← 여기서 호출!
     *    → UsernamePasswordAuthenticationToken 생성
     *    → SecurityContext에 인증 정보 설정
     */
    @Bean // Spring 컨테이너에서 관리하는 빈으로 등록
    public UserDetailsService userDetailsService() {
        // 🔑 람다 표현식으로 UserDetailsService 인터페이스 구현
        // ⚠️ 주의: 이 메서드는 JwtAuthenticationFilter에서만 호출됨!
        return email -> userRepository.findByEmail(email) // 이메일로 사용자 조회 (데이터베이스 호출)
                .map(user -> org.springframework.security.core.userdetails.User.builder() // 조회된 사용자로 UserDetails 객체 생성
                        .username(user.getEmail()) // 사용자명으로 이메일 설정
                        .password("") // 🚫 JWT 기반 인증이므로 비밀번호는 빈 문자열 (사용 안 함)
                        .authorities(user.getRoleKey()) // 🎆 사용자 권한 설정 (ROLE_USER, ROLE_ADMIN 등)
                        .build()) // UserDetails 객체 빌드 완료
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + email)); // 사용자 없을 시 예외 발생
    }
}