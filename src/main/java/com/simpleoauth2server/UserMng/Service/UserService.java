package com.simpleoauth2server.UserMng.Service;

import com.simpleoauth2server.Config.Jwt.JWTProvider;
import com.simpleoauth2server.GlobeAdvice.Exceptions.RandomExceptions;
import com.simpleoauth2server.GlobeAdvice.Exceptions.UserExistException;
import com.simpleoauth2server.Repo.UserRepository;

import com.simpleoauth2server.UserMng.Entity.User;
import com.simpleoauth2server.UserMng.dto.*;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JWTProvider jwtProvider;

    @Transactional
    public UserResponseDTO registerUser(UserRegistrationDTO registrationDTO) {
        // Check if username already exists
        if (userRepository.findByUsername(registrationDTO.getUsername()).isPresent()) {
            throw new IllegalArgumentException("Username already exists: " + registrationDTO.getUsername());
        }

        // Create and save user
        User user = new User();
        user.setUsername(registrationDTO.getUsername());
        user.setPassword(passwordEncoder.encode(registrationDTO.getPassword()));

        // Set email if provided
        if (registrationDTO.getEmail() != null) {
            user.setEmail(registrationDTO.getEmail());
        }

        // Set roles (add default USER role if none provided)
        if (registrationDTO.getRoles() == null || registrationDTO.getRoles().isEmpty()) {
            user.setRoles(Collections.singleton("USER"));
        } else {
            user.setRoles(new HashSet<>(registrationDTO.getRoles()));
        }

        // Set enabled status
        user.setEnabled(registrationDTO.getEnabled() != null ? registrationDTO.getEnabled() : true);

        user = userRepository.save(user);

        // Map to response DTO (without sensitive information)
        return mapToUserResponseDTO(user);
    }

    @Transactional
    public JwtResponseDTO authenticateUser(LoginRequestDTO loginRequest) {
        // Authenticate the user
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()
                )
        );

        // Set authentication in security context
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Generate tokens
        String accessToken = jwtProvider.generateAccessToken(authentication);
        String refreshToken = jwtProvider.generateRefreshToken(authentication);

        // Get user details
        User user = userRepository.findByUsername(loginRequest.getUsername())
                .orElseThrow(() -> new UserExistException("User not found"));
        UserResponseDTO userResponseDTO = mapToUserResponseDTO(user);

        // Create response
        JwtResponseDTO response = new JwtResponseDTO();
        response.setAccessToken(accessToken);
        response.setRefreshToken(refreshToken);
        response.setTokenType("Bearer");
        response.setUser(userResponseDTO);

        return response;
    }

    @Transactional
    public JwtResponseDTO refreshToken(TokenRefreshRequestDTO refreshRequest) throws RandomExceptions {
        String requestRefreshToken = refreshRequest.getRefreshToken();

        try {
            // Validate the refresh token
            if (!jwtProvider.validToken(requestRefreshToken, "REFRESH")) {
                throw new RandomExceptions("Invalid refresh token");
            }

            // Get username from token
            String username = jwtProvider.getUserName(requestRefreshToken);

            // Find the user
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new RandomExceptions("User not found with username: " + username));

            // Create authentication object
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    username, null, null);

            // Generate new access token
            String newAccessToken = jwtProvider.generateAccessToken(authentication);

            // Create response
            JwtResponseDTO response = new JwtResponseDTO();
            response.setAccessToken(newAccessToken);
            response.setRefreshToken(requestRefreshToken); // reuse the same refresh token
            response.setTokenType("Bearer");
            response.setUser(mapToUserResponseDTO(user));

            return response;

        } catch (Exception e) {
            throw new RandomExceptions("Failed to refresh token: " + e.getMessage());
        }
    }

    @Transactional(readOnly = true)
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    @Transactional(readOnly = true)
    public UserResponseDTO getUserById(UUID id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new UserExistException("User not found with id: " + id));
        return mapToUserResponseDTO(user);
    }

    @Transactional(readOnly = true)
    public UserResponseDTO getUserByUsername(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UserExistException("User not found with username: " + username));
        return mapToUserResponseDTO(user);
    }

    @Transactional(readOnly = true)
    public User getUserPlainByUsername(String username) {
       return userRepository.findByUsername(username)
                .orElseThrow(() -> new UserExistException("User not found with username: " + username));
    }

    @Transactional
    public void deleteUser(UUID id) {
        userRepository.deleteById(id);
    }

    @Transactional
    public UserResponseDTO updateUser(UUID id, UserUpdateDTO updateDTO) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new UserExistException("User not found with id: " + id));

        // Update fields if provided
        if (updateDTO.getUsername() != null) {
            // Check if the new username is already taken by another user
            userRepository.findByUsername(updateDTO.getUsername())
                    .ifPresent(existingUser -> {
                        if (!existingUser.getId().equals(id)) {
                            throw new IllegalArgumentException("Username already exists: " + updateDTO.getUsername());
                        }
                    });
            user.setUsername(updateDTO.getUsername());
        }

        if (updateDTO.getEmail() != null) {
            user.setEmail(updateDTO.getEmail());
        }

        if (updateDTO.getRoles() != null && !updateDTO.getRoles().isEmpty()) {
            user.setRoles(new HashSet<>(updateDTO.getRoles()));
        }

        if (updateDTO.getEnabled() != null) {
            user.setEnabled(updateDTO.getEnabled());
        }

        user = userRepository.save(user);
        return mapToUserResponseDTO(user);
    }

    @Transactional
    public UserResponseDTO changePassword(UUID id, PasswordChangeDTO passwordChangeDTO) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new UserExistException("User not found with id: " + id));

        // Verify current password
        if (!passwordEncoder.matches(passwordChangeDTO.getCurrentPassword(), user.getPassword())) {
            throw new IllegalArgumentException("Current password is incorrect");
        }

        // Update to new password
        user.setPassword(passwordEncoder.encode(passwordChangeDTO.getNewPassword()));
        user = userRepository.save(user);

        return mapToUserResponseDTO(user);
    }

    // Helper method to map User entity to UserResponseDTO
    private UserResponseDTO mapToUserResponseDTO(User user) {
        UserResponseDTO responseDTO = new UserResponseDTO();
        responseDTO.setId(user.getId());
        responseDTO.setUsername(user.getUsername());
        responseDTO.setEmail(user.getEmail());
        responseDTO.setRoles(user.getRoles());
        responseDTO.setEnabled(user.isEnabled());
        return responseDTO;
    }
}