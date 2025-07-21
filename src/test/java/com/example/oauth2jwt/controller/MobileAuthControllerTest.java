package com.example.oauth2jwt.controller;

import com.example.oauth2jwt.provider.JwtTokenProvider;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(MobileAuthController.class)
class MobileAuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private JwtTokenProvider jwtTokenProvider;

    @Test
    void verifyToken_WithValidHeader_ShouldReturnSuccess() throws Exception {
        // Given
        String validToken = "valid-jwt-token";
        String email = "test@example.com";

        when(jwtTokenProvider.validateToken(validToken)).thenReturn(true);
        when(jwtTokenProvider.getEmailFromToken(validToken)).thenReturn(email);

        // When & Then
        mockMvc.perform(get("/api/mobile/auth/verify")
                .header("Authorization", "Bearer " + validToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.message").value("토큰이 유효합니다."));
    }

    @Test
    void verifyToken_WithInvalidHeader_ShouldReturnUnauthorized() throws Exception {
        // Given
        String invalidToken = "invalid-jwt-token";

        when(jwtTokenProvider.validateToken(invalidToken)).thenReturn(false);

        // When & Then
        mockMvc.perform(get("/api/mobile/auth/verify")
                .header("Authorization", "Bearer " + invalidToken))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.valid").value(false))
                .andExpect(jsonPath("$.message").value("토큰이 유효하지 않습니다."));
    }

    @Test
    void verifyToken_WithoutAuthHeader_ShouldReturnUnauthorized() throws Exception {
        // When & Then
        mockMvc.perform(get("/api/mobile/auth/verify"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.valid").value(false))
                .andExpect(jsonPath("$.message").value("토큰이 유효하지 않습니다."));
    }

    @Test
    void logout_ShouldReturnSuccess() throws Exception {
        // Given
        String validToken = "valid-jwt-token";

        // When & Then
        mockMvc.perform(post("/api/mobile/auth/logout")
                .header("Authorization", "Bearer " + validToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("로그아웃이 완료되었습니다."));
    }

    @Test
    void logout_WithoutToken_ShouldStillReturnSuccess() throws Exception {
        // When & Then
        mockMvc.perform(post("/api/mobile/auth/logout"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("로그아웃이 완료되었습니다."));
    }
}