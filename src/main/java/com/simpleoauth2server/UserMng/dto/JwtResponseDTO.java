package com.simpleoauth2server.UserMng.dto;

import lombok.Data;

@Data
public class JwtResponseDTO {
    private String accessToken;
    private String refreshToken;
    private String tokenType;
    private UserResponseDTO user;
}