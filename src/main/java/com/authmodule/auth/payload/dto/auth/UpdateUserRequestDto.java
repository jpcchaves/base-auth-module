package com.authmodule.auth.payload.dto.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.hibernate.validator.constraints.Length;

public class UpdateUserRequestDto {
    @Size(max = 50, message = "O nome deve conter no máximo 50 caracteres!")
    private String name;

    @NotBlank(message = "A senha atual é obrigatória!")
    @Size(min = 6, message = "A senha deve conter pelo menos 6 caracteres!")
    private String currentPassword;

    @NotBlank(message = "A senha atual é obrigatória!")
    @Length(min = 6, message = "Senha deve conter pelo menos 6 caracteres!")
    private String password;

    public UpdateUserRequestDto() {
    }

    public UpdateUserRequestDto(String name, String currentPassword, String password) {
        this.name = name;
        this.currentPassword = currentPassword;
        this.password = password;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getCurrentPassword() {
        return currentPassword;
    }

    public void setCurrentPassword(String currentPassword) {
        this.currentPassword = currentPassword;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
