package com.simpleoauth2server.UserMng.dto;

import lombok.Data;

@Data
public class TokenRefreshRequestDTO {
    private String refreshToken;
}