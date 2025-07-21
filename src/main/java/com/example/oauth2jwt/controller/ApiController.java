package com.example.oauth2jwt.controller;

import com.example.oauth2jwt.dto.UserDto;
import com.example.oauth2jwt.service.AuthService;
import com.example.oauth2jwt.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class ApiController {

    private final UserService userService;
    private final AuthService authService;

    @GetMapping("/hello")
    public ResponseEntity<String> hello() {
        return ResponseEntity.ok("Hello OAuth2 JWT World!");
    }

    @GetMapping("/user/{id}")
    public ResponseEntity<UserDto> getUser(@PathVariable Long id) {
        return userService.findById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/me")
    public ResponseEntity<UserDto> getCurrentUser() {
        return authService.getCurrentUser()
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/auth/refresh")
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

    @PostMapping("/auth/validate")
    public ResponseEntity<Map<String, Object>> validateToken(@RequestBody Map<String, String> request) {
        String token = request.get("token");
        
        if (token == null || token.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "토큰이 필요합니다."));
        }
        
        boolean isValid = authService.isTokenValid(token);
        Map<String, Object> result = Map.of(
                "valid", isValid,
                "message", isValid ? "유효한 토큰입니다." : "유효하지 않은 토큰입니다."
        );
        
        return ResponseEntity.ok(result);
    }
}