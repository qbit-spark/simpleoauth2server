package com.simpleoauth2server.UserMng.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserRegistrationDTO {

    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    @Pattern(regexp = "^[a-zA-Z0-9._-]+$", message = "Username can only contain letters, numbers, dots, underscores, and hyphens")
    private String username;

    @NotBlank(message = "Password is required")
    @Size(min = 8, message = "Password must be at least 8 characters")
    @Pattern(regexp = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!]).*$",
            message = "Password must contain at least one digit, one lowercase letter, one uppercase letter, and one special character")
    private String password;

    @Email(message = "Email should be valid")
    private String email;

//    @Size(min = 10, max = 15, message = "Phone number must be between 10 and 15 digits")
//    @Pattern(regexp = "^[0-9+]+$", message = "Phone number can only contain digits and the plus sign")
//    private String phoneNumber;
//
//    private String firstName;
//
//    private String lastName;

    private Set<String> roles;

    private Boolean enabled = true;
//
//    // Optional fields for additional user information
//    private String company;
//
//    private String position;
//
//    // For consent and terms acceptance
//    private Boolean termsAccepted = false;
//
//    // For marketing preferences
//    private Boolean marketingEmails = false;
}