package com.simpleoauth2server.UserMng.dto;

import lombok.Data;

import java.util.Set;

@Data
public class UserRegistrationDTO {
    private String username;
    private String password;
    private Set<String> roles;
    private Boolean enabled = true;
}