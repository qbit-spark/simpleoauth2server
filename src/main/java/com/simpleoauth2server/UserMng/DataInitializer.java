package com.simpleoauth2server.UserMng;

import com.simpleoauth2server.Repo.UserRepository;
import com.simpleoauth2server.UserMng.Entity.User;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
@RequiredArgsConstructor
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {
        // Only add users if repo is empty
        if (userRepository.count() == 0) {
            // Create admin user
            User admin = new User();
            admin.setUsername("admin");
            admin.setPassword(passwordEncoder.encode("admin"));
            admin.setEnabled(true);
            admin.setRoles(Set.of("ADMIN", "USER"));
            userRepository.save(admin);

            // Create regular user
            User user = new User();
            user.setUsername("user");
            user.setPassword(passwordEncoder.encode("password"));
            user.setEnabled(true);
            user.setRoles(Set.of("USER"));
            userRepository.save(user);

            System.out.println("Created default users");
        }
    }
}