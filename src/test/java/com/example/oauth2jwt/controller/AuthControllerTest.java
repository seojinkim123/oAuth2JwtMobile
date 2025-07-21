package com.example.oauth2jwt.controller;

import com.example.oauth2jwt.service.AuthService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AuthController.class)
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AuthService authService;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void refreshToken_ShouldReturnNewTokens() throws Exception {
        // Given
        String refreshToken = "valid-refresh-token";
        Map<String, String> request = Map.of("refreshToken", refreshToken);
        Map<String, String> response = Map.of(
            "accessToken", "new-access-token",
            "refreshToken", "new-refresh-token",
            "message", "토큰이 성공적으로 갱신되었습니다."
        );

        when(authService.refreshToken(refreshToken)).thenReturn(response);

        // When & Then
        mockMvc.perform(post("/api/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("new-access-token"))
                .andExpect(jsonPath("$.refreshToken").value("new-refresh-token"));
    }

    @Test
    void validateToken_ShouldReturnValidStatus() throws Exception {
        // Given
        String token = "valid-token";
        Map<String, String> request = Map.of("token", token);

        when(authService.isTokenValid(token)).thenReturn(true);

        // When & Then
        mockMvc.perform(post("/api/auth/validate")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.message").value("유효한 토큰입니다."));
    }

    @Test
    void refreshToken_WithInvalidToken_ShouldReturnBadRequest() throws Exception {
        // Given
        String refreshToken = "invalid-refresh-token";
        Map<String, String> request = Map.of("refreshToken", refreshToken);
        Map<String, String> response = Map.of("error", "유효하지 않은 리프레시 토큰입니다.");

        when(authService.refreshToken(refreshToken)).thenReturn(response);

        // When & Then
        mockMvc.perform(post("/api/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("유효하지 않은 리프레시 토큰입니다."));
    }
}