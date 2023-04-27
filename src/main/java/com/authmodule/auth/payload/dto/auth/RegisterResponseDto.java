package com.authmodule.auth.payload.dto.auth;

public class RegisterResponseDto {
    private Long id;
    private String name;
    private String username;
    private String email;
    private Boolean isAdmin;

    public RegisterResponseDto() {
    }

    public RegisterResponseDto(Long id,
                               String name,
                               String username,
                               String email,
                               Boolean isAdmin) {
        this.id = id;
        this.name = name;
        this.username = username;
        this.email = email;
        this.isAdmin = isAdmin;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public Boolean getAdmin() {
        return isAdmin;
    }

    public void setAdmin(Boolean admin) {
        isAdmin = admin;
    }
}
