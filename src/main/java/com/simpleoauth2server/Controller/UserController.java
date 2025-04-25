package com.simpleoauth2server.Controller;

import com.simpleoauth2server.ClientMng.Entity.User;
import com.simpleoauth2server.ClientMng.Service.UserService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    /**
     * Register a new user
     */
    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody UserRegistrationRequest request) {
        // Check if username already exists
        if (userService.findByUsername(request.getUsername()).isPresent()) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Username already exists");
            return ResponseEntity.badRequest().body(error);
        }

        // Create new user
        User user = userService.createUser(
                request.getUsername(),
                request.getPassword(),
                request.getRoles()
        );

        // Return user data (without password)
        UserResponse response = mapToUserResponse(user);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Get all users (admin only)
     */
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<UserResponse>> getAllUsers() {
        List<User> users = userService.findAllUsers();
        List<UserResponse> response = users.stream()
                .map(this::mapToUserResponse)
                .toList();
        return ResponseEntity.ok(response);
    }

    /**
     * Get user by username
     */
    @GetMapping("/{username}")
    public ResponseEntity<UserResponse> getUserByUsername(@PathVariable String username) {
        User user = userService.findByUsername(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        return ResponseEntity.ok(mapToUserResponse(user));
    }

    /**
     * Update user
     */
    @PutMapping("/{username}")
    @PreAuthorize("hasRole('ADMIN') or #username == authentication.name")
    public ResponseEntity<UserResponse> updateUser(
            @PathVariable String username,
            @Valid @RequestBody UserUpdateRequest request) {

        User user = userService.findByUsername(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        // Update user fields
        if (request.getPassword() != null && !request.getPassword().isEmpty()) {
            userService.updatePassword(user, request.getPassword());
        }

        // Only admins can update roles
        if (request.getRoles() != null && !request.getRoles().isEmpty()) {
            userService.updateRoles(user, request.getRoles());
        }

        return ResponseEntity.ok(mapToUserResponse(user));
    }

    /**
     * Delete user
     */
    @DeleteMapping("/{username}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> deleteUser(@PathVariable String username) {
        User user = userService.findByUsername(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        userService.deleteUser(user);

        Map<String, String> response = new HashMap<>();
        response.put("message", "User deleted successfully");
        return ResponseEntity.ok(response);
    }

    /**
     * Map User entity to UserResponse DTO
     */
    private UserResponse mapToUserResponse(User user) {
        UserResponse response = new UserResponse();
        response.setId(user.getId());
        response.setUsername(user.getUsername());
        response.setRoles(user.getRoles());
        response.setEnabled(user.isEnabled());
        return response;
    }

    /**
     * DTO for user registration requests
     */
    @Data
    public static class UserRegistrationRequest {
        @NotBlank(message = "Username is required")
        @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
        private String username;

        @NotBlank(message = "Password is required")
        @Size(min = 6, message = "Password must be at least 6 characters")
        private String password;

        private List<String> roles;
    }

    /**
     * DTO for user update requests
     */
    @Data
    public static class UserUpdateRequest {
        @Size(min = 6, message = "Password must be at least 6 characters")
        private String password;

        private List<String> roles;
    }

    /**
     * DTO for user responses
     */
    @Data
    public static class UserResponse {
        private String id;
        private String username;
        private java.util.Set<String> roles;
        private boolean enabled;
    }
}