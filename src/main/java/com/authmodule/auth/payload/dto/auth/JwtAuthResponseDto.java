package com.authmodule.auth.payload.dto.auth;

import com.authmodule.auth.payload.dto.user.UserDto;

public class JwtAuthResponseDto {
    private String accessToken;
    private UserDto user;

    public JwtAuthResponseDto() {
    }

    public JwtAuthResponseDto(String accessToken,
                              UserDto user) {
        this.accessToken = accessToken;
        this.user = user;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public UserDto getUser() {
        return user;
    }

    public void setUser(UserDto user) {
        this.user = user;
    }
}
