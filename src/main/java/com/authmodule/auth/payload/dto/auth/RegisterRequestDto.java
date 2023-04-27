package com.authmodule.auth.payload.dto.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.hibernate.validator.constraints.Length;

public class RegisterRequestDto {
    @Size(max = 50, message = "O nome deve conter no máximo 50 caracteres!")
    private String name;

    @Size(max = 50, message = "O nome deve conter no máximo 50 caracteres!")
    @NotBlank(message = "O nome de usuário é obrigatório!")
    private String username;

    @NotBlank(message = "O email é obrigatório!")
    @Email(message = "Insira um email válido!")
    private String email;

    @NotBlank(message = "A senha é obrigatória!")
    @NotBlank(message = "A senha atual é obrigatória!")
    @Length(min = 6, message = "Senha deve conter pelo menos 6 caracteres!")
    private String password;

    @NotBlank(message = "A confirmação de senha é obrigatória!")
    @Length(min = 6, message = "Senha deve conter pelo menos 6 caracteres!")
    private String confirmPassword;

    public RegisterRequestDto() {
    }

    public RegisterRequestDto(String name,
                              String username,
                              String email,
                              String password,
                              String confirmPassword) {
        this.name = name;
        this.username = username;
        this.email = email;
        this.password = password;
        this.confirmPassword = confirmPassword;
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

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getConfirmPassword() {
        return confirmPassword;
    }

    public void setConfirmPassword(String confirmPassword) {
        this.confirmPassword = confirmPassword;
    }
}
