package com.authmodule.auth.services;

import com.authmodule.auth.payload.dto.auth.*;

public interface AuthService {
    JwtAuthResponseDto login(LoginDto loginDto);

    RegisterResponseDto register(RegisterRequestDto registerDto);

    UpdateUserResponseDto update(UpdateUserRequestDto updateUserDto, Long id);
}
