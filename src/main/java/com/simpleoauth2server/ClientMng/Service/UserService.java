package com.simpleoauth2server.ClientMng.Service;


import com.simpleoauth2server.ClientMng.Entity.User;
import com.simpleoauth2server.ClientMng.Repo.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * Create a new user
     */
    @Transactional
    public User createUser(String username, String password, List<String> roles) {
        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));

        // Default to USER role if none provided
        user.setRoles(roles != null && !roles.isEmpty()
                ? new java.util.HashSet<>(roles)
                : Collections.singleton("USER"));

        user.setEnabled(true);
        return userRepository.save(user);
    }

    /**
     * Find user by username
     */
    @Transactional(readOnly = true)
    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    /**
     * Get all users
     */
    @Transactional(readOnly = true)
    public List<User> findAllUsers() {
        return userRepository.findAll();
    }

    /**
     * Update user password
     */
    @Transactional
    public User updatePassword(User user, String newPassword) {
        user.setPassword(passwordEncoder.encode(newPassword));
        return userRepository.save(user);
    }

    /**
     * Update user roles
     */
    @Transactional
    public User updateRoles(User user, List<String> roles) {
        if (roles != null && !roles.isEmpty()) {
            user.setRoles(new java.util.HashSet<>(roles));
            return userRepository.save(user);
        }
        return user;
    }

    /**
     * Enable or disable a user
     */
    @Transactional
    public User setUserEnabled(User user, boolean enabled) {
        user.setEnabled(enabled);
        return userRepository.save(user);
    }

    /**
     * Delete a user
     */
    @Transactional
    public void deleteUser(User user) {
        userRepository.delete(user);
    }

    /**
     * Delete a user by username
     */
    @Transactional
    public void deleteUserByUsername(String username) {
        userRepository.findByUsername(username)
                .ifPresent(userRepository::delete);
    }

    /**
     * Check if user has specific role
     */
    public boolean hasRole(User user, String role) {
        return user.getRoles().contains(role);
    }

    /**
     * Add role to user
     */
    @Transactional
    public User addRole(User user, String role) {
        Set<String> roles = user.getRoles();
        roles.add(role);
        user.setRoles(roles);
        return userRepository.save(user);
    }

    /**
     * Remove role from user
     */
    @Transactional
    public User removeRole(User user, String role) {
        Set<String> roles = user.getRoles();
        roles.remove(role);
        // Ensure user has at least one role
        if (roles.isEmpty()) {
            roles.add("USER");
        }
        user.setRoles(roles);
        return userRepository.save(user);
    }
}