package com.example.oauth2jwt.dto;


import com.example.oauth2jwt.entity.Role;
import com.example.oauth2jwt.entity.User;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class UserDto {
    private Long id;
    private String email;
    private String name;
    private String picture;
    private Role role;
    private LocalDateTime createdDate;
    private LocalDateTime modifiedDate;

    public static UserDto from(User user) {
        return UserDto.builder()
                .id(user.getId())
                .email(user.getEmail())
                .name(user.getName())
                .picture(user.getPicture())
                .role(user.getRole())
                .createdDate(user.getCreatedDate())
                .modifiedDate(user.getModifiedDate())
                .build();
    }
}