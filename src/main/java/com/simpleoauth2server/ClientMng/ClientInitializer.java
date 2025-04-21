package com.simpleoauth2server.ClientMng;

import com.simpleoauth2server.ClientMng.Repo.RegisteredClientEntityRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class ClientInitializer implements CommandLineRunner {

    private final RegisteredClientRepository registeredClientRepository;
    private final RegisteredClientEntityRepository clientEntityRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {
        // Always clean out existing clients and create a new one
        try {
            // Force delete all existing clients
            clientEntityRepository.deleteAll();

            // Create default client with explicit TokenSettings
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
                    .tokenSettings(TokenSettings.builder()
                            .accessTokenTimeToLive(Duration.ofMinutes(30))
                            .refreshTokenTimeToLive(Duration.ofDays(1))
                            .authorizationCodeTimeToLive(Duration.ofMinutes(5))
                            .build())
                    .build();

            registeredClientRepository.save(oidcClient);

           // Lets print all client details in one println by concatenating the string
            System.out.println("Client ID: " + oidcClient.getClientId() +
                    "\nClient Secret: " + oidcClient.getClientSecret() +
                    "\nRedirect URI: " + oidcClient.getRedirectUris() +
                    "\nScopes: " + oidcClient.getScopes() +
                    "\nAccess Token TTL: " + oidcClient.getTokenSettings().getAccessTokenTimeToLive() +
                    "\nRefresh Token TTL: " + oidcClient.getTokenSettings().getRefreshTokenTimeToLive());

        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("Failed to initialize client: " + e.getMessage());
        }
    }
}