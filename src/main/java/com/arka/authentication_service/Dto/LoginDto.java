package com.arka.authentication_service.Dto;

import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

@NoArgsConstructor
@Data
public class LoginDto {
    private String email;
    private String password;

}
