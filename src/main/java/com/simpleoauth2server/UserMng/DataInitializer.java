package com.simpleoauth2server.UserMng;

import com.simpleoauth2server.ClientMng.Repo.RegisteredClientEntityRepository;
import com.simpleoauth2server.Repo.UserRepository;
import com.simpleoauth2server.UserMng.Entity.User;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.util.Set;
import java.util.UUID;

@Order(2)
@Component
@RequiredArgsConstructor
public class DataInitializer implements CommandLineRunner {

    private static final Logger logger = LoggerFactory.getLogger(DataInitializer.class);

    // User-related dependencies
    private final UserRepository userRepository;

    // Client-related dependencies
    private final RegisteredClientRepository registeredClientRepository;

    // Shared dependencies
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public void run(String... args) {
        try {
            // Step 1: Initialize users
            initializeUsers();

            // Step 2: Initialize OAuth2 clients
            initializeOAuthClients();

            logger.info("Data initialization completed successfully");
        } catch (Exception e) {
            logger.error("Error during data initialization", e);
            System.err.println("Data initialization failed: " + e.getMessage());
        }
    }

    private void initializeUsers() {
        // Only add users if repo is empty
        if (userRepository.count() == 0) {
            logger.info("Initializing default users");

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

            logger.info("Created default users: admin, user");
        } else {
            logger.info("Users already exist, skipping user initialization");
        }
    }

    private void initializeOAuthClients() {
        // Check if default client already exists
        if (registeredClientRepository.findByClientId("client") == null) {
            logger.info("Initializing default OAuth2 client");

            // Create TokenSettings with explicit duration values
            TokenSettings tokenSettings = TokenSettings.builder()
                    .accessTokenTimeToLive(Duration.ofMinutes(30))
                    .refreshTokenTimeToLive(Duration.ofDays(1))
                    .authorizationCodeTimeToLive(Duration.ofMinutes(5))
                    .build();

            // Create the client with a new UUID
            RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("client")
                    .clientSecret(passwordEncoder.encode("secret"))
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .redirectUri("http://localhost:8080/login/oauth2/code/client")
                    .scope(OidcScopes.OPENID)
                    .scope("read")
                    .clientSettings(ClientSettings.builder()
                            .requireAuthorizationConsent(true)
                            .build())
                    .tokenSettings(tokenSettings)
                    .build();

            // Save the client
            registeredClientRepository.save(oidcClient);

            logger.info("Successfully initialized default OAuth2 client");
            System.out.println("Client ID: " + oidcClient.getClientId() +
                    "\nClient Secret: secret" +
                    "\nRedirect URI: " + oidcClient.getRedirectUris() +
                    "\nScopes: " + oidcClient.getScopes() +
                    "\nAccess Token TTL: " + tokenSettings.getAccessTokenTimeToLive() +
                    "\nRefresh Token TTL: " + tokenSettings.getRefreshTokenTimeToLive());
        } else {
            logger.info("OAuth2 client already exists, skipping client initialization");
        }
    }
}