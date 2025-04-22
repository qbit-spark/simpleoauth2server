package com.simpleoauth2server.UserMng.Service;

import com.simpleoauth2server.Repo.UserRepository;

import com.simpleoauth2server.UserMng.Entity.User;
import com.simpleoauth2server.UserMng.dto.UserRegistrationDTO;
import lombok.RequiredArgsConstructor;
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

    @Transactional
    public User registerUser(UserRegistrationDTO registrationDTO) {
        // Check if username already exists
        if (userRepository.findByUsername(registrationDTO.getUsername()).isPresent()) {
            throw new IllegalArgumentException("Username already exists: " + registrationDTO.getUsername());
        }

        // Create and save user
        User user = new User();
        user.setUsername(registrationDTO.getUsername());
        user.setPassword(passwordEncoder.encode(registrationDTO.getPassword()));

        // Set roles (add default USER role if none provided)
        if (registrationDTO.getRoles() == null || registrationDTO.getRoles().isEmpty()) {
            user.setRoles(Collections.singleton("USER"));
        } else {
            user.setRoles(new HashSet<>(registrationDTO.getRoles()));
        }

        // Set enabled status
        user.setEnabled(registrationDTO.getEnabled() != null ? registrationDTO.getEnabled() : true);

        return userRepository.save(user);
    }

    @Transactional(readOnly = true)
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    @Transactional(readOnly = true)
    public User getUserById(UUID id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("User not found with id: " + id));
    }

    @Transactional(readOnly = true)
    public User getUserByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found with username: " + username));
    }

    @Transactional
    public void deleteUser(UUID id) {
        userRepository.deleteById(id);
    }
}