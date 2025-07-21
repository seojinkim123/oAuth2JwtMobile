package com.example.oauth2jwt.controller;

import com.example.oauth2jwt.provider.JwtTokenProvider;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.web.servlet.MockMvc;

import jakarta.servlet.http.Cookie;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(WebAuthController.class)
class WebAuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private JwtTokenProvider jwtTokenProvider;

    @Test
    void verifyToken_WithValidCookie_ShouldReturnSuccess() throws Exception {
        // Given
        String validToken = "valid-jwt-token";
        String email = "test@example.com";
        Cookie tokenCookie = new Cookie("accessToken", validToken);

        when(jwtTokenProvider.validateToken(validToken)).thenReturn(true);
        when(jwtTokenProvider.getEmailFromToken(validToken)).thenReturn(email);

        // When & Then
        mockMvc.perform(get("/api/web/auth/verify")
                .cookie(tokenCookie))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.message").value("토큰이 유효합니다."));
    }

    @Test
    void verifyToken_WithInvalidCookie_ShouldReturnUnauthorized() throws Exception {
        // Given
        String invalidToken = "invalid-jwt-token";
        Cookie tokenCookie = new Cookie("accessToken", invalidToken);

        when(jwtTokenProvider.validateToken(invalidToken)).thenReturn(false);

        // When & Then
        mockMvc.perform(get("/api/web/auth/verify")
                .cookie(tokenCookie))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.valid").value(false))
                .andExpect(jsonPath("$.message").value("토큰이 유효하지 않습니다."));
    }

    @Test
    void logout_ShouldClearCookies() throws Exception {
        // When & Then
        mockMvc.perform(post("/api/web/auth/logout"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("로그아웃이 완료되었습니다."))
                .andExpect(cookie().maxAge("accessToken", 0))
                .andExpect(cookie().maxAge("refreshToken", 0));
    }
}