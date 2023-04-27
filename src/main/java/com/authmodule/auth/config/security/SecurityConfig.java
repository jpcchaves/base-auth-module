package com.authmodule.auth.config.security;

import com.authmodule.auth.security.CustomAccessDeniedHandler;
import com.authmodule.auth.security.JwtAuthenticationEntrypoint;
import com.authmodule.auth.security.JwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    private final UserDetailsService userDetailsService;
    private final JwtAuthenticationEntrypoint authenticationEntryPoint;
    private final CustomAccessDeniedHandler customAccessDeniedHandler;
    private final JwtAuthenticationFilter authenticationFilter;


    public SecurityConfig(UserDetailsService userDetailsService,
                          JwtAuthenticationEntrypoint authenticationEntryPoint,
                          CustomAccessDeniedHandler customAccessDeniedHandler,
                          JwtAuthenticationFilter authenticationFilter) {
        this.userDetailsService = userDetailsService;
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.customAccessDeniedHandler = customAccessDeniedHandler;
        this.authenticationFilter = authenticationFilter;
    }

    @Bean
    public static PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .headers()
                .frameOptions()
                .disable()
                .and()
                .cors()
                .and()
                .httpBasic()
                .disable()
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorize ->
                        authorize
                                .requestMatchers("/api/v1/auth/**", "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html")
                                .permitAll()
                                .anyRequest()
                                .authenticated()
                )
                .exceptionHandling(exception ->
                        exception
                                .authenticationEntryPoint(authenticationEntryPoint)
                                .accessDeniedHandler(customAccessDeniedHandler)
                )
                .sessionManagement(session ->
                        session
                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .cors();

        http.addFilterBefore(authenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
