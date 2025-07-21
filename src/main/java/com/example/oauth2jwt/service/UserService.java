package com.example.oauth2jwt.service;

import com.example.oauth2jwt.dto.UserDto;
import com.example.oauth2jwt.entity.User;
import com.example.oauth2jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class UserService {

    private final UserRepository userRepository;

    /**
     * 이메일로 사용자 정보 조회
     * 
     * 프로세스 흐름:
     * 이전: AuthService의 getCurrentUser 또는 JwtAuthenticationFilter에서 사용자 인증 후 호출 (인가)
     * 현재: 데이터베이스에서 이메일로 사용자 조회 -> UserDto로 변환 (인가)
     * 이후: 조회된 사용자 정보로 UserDetails 생성 또는 API 응답 반환 (인가)
     */
    public Optional<UserDto> findByEmail(String email) {
        return userRepository.findByEmail(email)
                .map(UserDto::from);
    }

    /**
     * ID로 사용자 정보 조회
     * 
     * 프로세스: 데이터베이스에서 사용자 ID로 조회 -> UserDto로 변환 (인가)
     */
    public Optional<UserDto> findById(Long id) {
        return userRepository.findById(id)
                .map(UserDto::from);
    }

    /**
     * 사용자 정보 저장
     * 
     * 프로세스 흐름:
     * 이전: OAuth2AuthenticationSuccessHandler에서 새로운 사용자 생성 또는 기존 사용자 업데이트 후 호출 (인증)
     * 현재: 데이터베이스에 사용자 정보 저장 -> UserDto로 변환 후 반환 (인증)
     * 이후: JWT 토큰 생성 및 쿠키 설정 프로세스 진행 (인증)
     */
    @Transactional
    public UserDto saveUser(User user) {
        User savedUser = userRepository.save(user);
        return UserDto.from(savedUser);
    }
}