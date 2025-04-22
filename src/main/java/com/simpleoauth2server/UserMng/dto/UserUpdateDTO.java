package com.simpleoauth2server.UserMng.dto;

import lombok.Data;

import java.util.Set;

@Data
public class UserUpdateDTO {
    private String username;
    private String email;
    private Set<String> roles;
    private Boolean enabled;
}
