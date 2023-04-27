package com.authmodule.auth.services.impl;

import com.authmodule.auth.entities.Role;
import com.authmodule.auth.entities.User;
import com.authmodule.auth.exceptions.BadRequestException;
import com.authmodule.auth.exceptions.ResourceNotFoundException;
import com.authmodule.auth.payload.dto.auth.*;
import com.authmodule.auth.payload.dto.role.RoleDto;
import com.authmodule.auth.payload.dto.user.UserDto;
import com.authmodule.auth.repositories.RoleRepository;
import com.authmodule.auth.repositories.UserRepository;
import com.authmodule.auth.security.JwtTokenProvider;
import com.authmodule.auth.services.AuthService;
import com.authmodule.auth.utils.mapper.MapperUtils;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

@Service
public class AuthServiceImpl implements AuthService {
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final MapperUtils mapperUtils;
    private final JwtTokenProvider jwtTokenProvider;

    public AuthServiceImpl(AuthenticationManager authenticationManager,
                           UserRepository userRepository,
                           RoleRepository roleRepository,
                           PasswordEncoder passwordEncoder,
                           MapperUtils mapperUtils,
                           JwtTokenProvider jwtTokenProvider) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.mapperUtils = mapperUtils;
        this.jwtTokenProvider = jwtTokenProvider;
    }


    @Override
    public JwtAuthResponseDto login(LoginDto loginDto) {
        try {
            Authentication authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(
                            loginDto.getUsernameOrEmail(), loginDto.getPassword()
                    ));
            SecurityContextHolder.getContext().setAuthentication(authentication);

            String token = jwtTokenProvider.generateToken(authentication);

            User user = userRepository
                    .findByUsernameOrEmail(loginDto.getUsernameOrEmail(), loginDto.getUsernameOrEmail())
                    .orElseThrow(() -> new ResourceNotFoundException("User not found with the given username or email: " + loginDto.getUsernameOrEmail()));

            UserDto userDto = copyPropertiesFromUserToUserDto(user);

            JwtAuthResponseDto jwtAuthResponseDto = new JwtAuthResponseDto();

            jwtAuthResponseDto.setAccessToken(token);
            jwtAuthResponseDto.setUser(userDto);

            return jwtAuthResponseDto;
        } catch (AuthenticationException ex) {
            throw new BadCredentialsException("Invalid username, email or password");
        }
    }

    @Override
    public RegisterResponseDto register(RegisterRequestDto registerDto) {
        // verify if user already registered
        if (userRepository.existsByUsername(registerDto.getUsername())) {
            throw new BadRequestException("Já existe um usuário cadastrado com o usuário informado");
        }

        // check if email already registered
        if (userRepository.existsByEmail(registerDto.getEmail())) {
            throw new BadRequestException("Já existe um usuário cadastrado com o email informado");
        }

        if (!Objects.equals(registerDto.getPassword(), registerDto.getConfirmPassword())) {
            throw new BadRequestException("As senhas não são iguais!");
        }

        Set<Role> roles = new HashSet<>();
        Optional<Role> userRole = roleRepository.findByName("ROLE_USER");

        User user = copyPropertiesFromRegisterDtoToUser(registerDto);

        if (userRole.isPresent()) {
            roles.add(userRole.get());
            user.setRoles(roles);
        }

        user.setAdmin(false);

        User newUser = userRepository.save(user);

        return mapperUtils.parseObject(newUser, RegisterResponseDto.class);
    }

    @Override
    public UpdateUserResponseDto update(UpdateUserRequestDto updateUserDto, Long id) {
        User user = userRepository
                .findById(id)
                .orElseThrow(
                        () -> new ResourceNotFoundException("User not found with the given id: " + id)
                );

        if (passwordsMatches(updateUserDto.getCurrentPassword(), user.getPassword())) {

            user.setName(updateUserDto.getName());
            user.setPassword(passwordEncoder.encode(updateUserDto.getPassword()));
            user.setAdmin(false);
            user.setRoles(user.getRoles());

            UpdateUserResponseDto response = mapperUtils.parseObject(userRepository.save(user), UpdateUserResponseDto.class);

            response.setMessage("User updarted successfully");

            return response;
        } else {
            throw new BadRequestException("Current password doesn't match");
        }
    }

    private UserDto copyPropertiesFromUserToUserDto(User user) {
        UserDto userDto = new UserDto();
        userDto.setId(user.getId());
        userDto.setEmail(user.getEmail());
        userDto.setName(user.getName());
        userDto.setUsername(user.getUsername());
        userDto.setRoles(mapperUtils.parseSetObjects(user.getRoles(), RoleDto.class));
        userDto.setAdmin(user.getAdmin());
        return userDto;
    }

    private User copyPropertiesFromRegisterDtoToUser(RegisterRequestDto registerDto) {
        User user = new User();
        user.setName(registerDto.getName());
        user.setEmail(registerDto.getEmail());
        user.setUsername(registerDto.getUsername());
        user.setPassword(passwordEncoder.encode(registerDto.getPassword()));
        return user;
    }

    private Boolean passwordsMatches(String currentPassword, String password) {
        return passwordEncoder.matches(currentPassword, password);
    }
}
