package com.authmodule.auth.payload.dto.user;

import com.authmodule.auth.payload.dto.role.RoleDto;

import java.util.Set;

public class UserDto {
    private Long id;
    private String name;
    private String username;
    private String email;
    private Boolean isAdmin;
    private Set<RoleDto> roles;

    public UserDto() {
    }

    public UserDto(Long id,
                   String name,
                   String username,
                   String email,
                   Boolean isAdmin,
                   Set<RoleDto> roles) {
        this.id = id;
        this.name = name;
        this.username = username;
        this.email = email;
        this.isAdmin = isAdmin;
        this.roles = roles;
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

    public Set<RoleDto> getRoles() {
        return roles;
    }

    public void setRoles(Set<RoleDto> roles) {
        this.roles = roles;
    }
}
