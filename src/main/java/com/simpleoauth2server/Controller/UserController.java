package com.simpleoauth2server.Controller;

import com.simpleoauth2server.GlobeAdvice.Exceptions.RandomExceptions;
import com.simpleoauth2server.GlobeAdvice.Exceptions.UserExistException;
import com.simpleoauth2server.UserMng.dto.*;
import com.simpleoauth2server.UserMng.Entity.User;
import com.simpleoauth2server.UserMng.Service.UserService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    /**
     * Public endpoints for authentication
     */
    @PostMapping("/auth/register")
    public ResponseEntity<UserResponseDTO> registerUser(@Valid @RequestBody UserRegistrationDTO registrationDTO) {
        try {
            UserResponseDTO user = userService.registerUser(registrationDTO);
            return new ResponseEntity<>(user, HttpStatus.CREATED);
        } catch (IllegalArgumentException e) {
            throw e; // Will be handled by global exception handler
        }
    }

    @PostMapping("/auth/login")
    public ResponseEntity<JwtResponseDTO> authenticateUser(@Valid @RequestBody LoginRequestDTO loginRequest) {
        JwtResponseDTO response = userService.authenticateUser(loginRequest);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/auth/refresh")
    public ResponseEntity<JwtResponseDTO> refreshToken(@Valid @RequestBody TokenRefreshRequestDTO request) throws RandomExceptions {
        try {
            JwtResponseDTO response = userService.refreshToken(request);
            return ResponseEntity.ok(response);
        } catch (RandomExceptions e) {
            throw e; // Will be handled by global exception handler
        }
    }

    /**
     * Endpoints for user management (protected)
     */
    @GetMapping("/users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<User>> getAllUsers() {
        List<User> users = userService.getAllUsers();
        return new ResponseEntity<>(users, HttpStatus.OK);
    }

    @GetMapping("/users/{id}")
    @PreAuthorize("hasRole('ADMIN') or @userSecurity.isCurrentUser(#id)")
    public ResponseEntity<UserResponseDTO> getUserById(@PathVariable UUID id) {
        try {
            UserResponseDTO user = userService.getUserById(id);
            return new ResponseEntity<>(user, HttpStatus.OK);
        } catch (UserExistException e) {
            throw e; // Will be handled by global exception handler
        }
    }

    @GetMapping("/users/me")
    public ResponseEntity<UserResponseDTO> getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String currentUsername = authentication.getName();

        try {
            UserResponseDTO user = userService.getUserByUsername(currentUsername);
            return new ResponseEntity<>(user, HttpStatus.OK);
        } catch (UserExistException e) {
            throw e; // Will be handled by global exception handler
        }
    }

    @PutMapping("/users/{id}")
    @PreAuthorize("hasRole('ADMIN') or @userSecurity.isCurrentUser(#id)")
    public ResponseEntity<UserResponseDTO> updateUser(
            @PathVariable UUID id,
            @Valid @RequestBody UserUpdateDTO updateDTO) {
        try {
            UserResponseDTO user = userService.updateUser(id, updateDTO);
            return new ResponseEntity<>(user, HttpStatus.OK);
        } catch (UserExistException | IllegalArgumentException e) {
            throw e; // Will be handled by global exception handler
        }
    }

    @PostMapping("/users/{id}/change-password")
    @PreAuthorize("@userSecurity.isCurrentUser(#id)")
    public ResponseEntity<UserResponseDTO> changePassword(
            @PathVariable UUID id,
            @Valid @RequestBody PasswordChangeDTO passwordChangeDTO) {
        try {
            UserResponseDTO user = userService.changePassword(id, passwordChangeDTO);
            return ResponseEntity.ok(user);
        } catch (UserExistException | IllegalArgumentException e) {
            throw e; // Will be handled by global exception handler
        }
    }

    @DeleteMapping("/users/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteUser(@PathVariable UUID id) {
        try {
            userService.deleteUser(id);
            return new ResponseEntity<>(HttpStatus.NO_CONTENT);
        } catch (UserExistException e) {
            throw e; // Will be handled by global exception handler
        }
    }
}