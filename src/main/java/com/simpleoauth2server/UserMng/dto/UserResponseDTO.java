package com.simpleoauth2server.UserMng.dto;

import lombok.Data;

import java.util.Set;
import java.util.UUID;

@Data
public class UserResponseDTO {
    private UUID id;
    private String username;
    private String email;
    private Set<String> roles;
    private boolean enabled;
}