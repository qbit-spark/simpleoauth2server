package com.simpleoauth2server.ClientMng.Service;

import com.simpleoauth2server.ClientMng.Entity.CustomRegisteredClient;
import com.simpleoauth2server.ClientMng.Repo.RegisteredClientEntityRepository;
import com.simpleoauth2server.ClientMng.dto.ClientRegistrationDTO;


import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.RandomStringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.util.*;

@Service
@RequiredArgsConstructor
public class RegisteredClientRepositoryIMPL implements RegisteredClientRepository {

    private static final Logger logger = LoggerFactory.getLogger(RegisteredClientRepositoryIMPL.class);

    private final RegisteredClientEntityRepository repository;
    private final PasswordEncoder passwordEncoder;

    /**
     * Register a new OAuth client for the authenticated user
     */
    @Transactional
    public CustomRegisteredClient registerClient(ClientRegistrationDTO registrationDTO) {
        // Generate client ID with a format like "clt_xxxxxxxx"
        String clientId = "clt_" + RandomStringUtils.randomAlphanumeric(8);

        // Generate a more complex client secret
        String clientSecret = RandomStringUtils.randomAlphanumeric(70);


        // Create a new client entity
        CustomRegisteredClient clientEntity = new CustomRegisteredClient();
        clientEntity.setClientId(clientId);
        clientEntity.setClientSecret(clientSecret);
        clientEntity.setClientName(registrationDTO.getClientName());
        clientEntity.setRedirectUri(registrationDTO.getRedirectUri());
        clientEntity.setRequireProofKey(registrationDTO.isRequireProofKey());
        clientEntity.setAuthorizationGrantType(registrationDTO.getAuthorizationGrantType());
        clientEntity.setTokenFormat(registrationDTO.getTokenFormat());


        // Save the entity
        return repository.saveAndFlush(clientEntity);
    }

    @Transactional(readOnly = true)
    public List<CustomRegisteredClient> getAllClients() {
        return repository.findAll();
    }


    @Override
    public void save(RegisteredClient registeredClient) {
      // This method should be ignored, as we are using the CustomRegisteredClient entity
    }

    @Override
    public RegisteredClient findById(String id) {
        return mapToClient(repository.findById(id).orElseThrow());
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return mapToClient(repository.findByClientId(clientId).orElseThrow());
    }

    private RegisteredClient mapToClient(CustomRegisteredClient client) {
        // Determine authorization grant type
        AuthorizationGrantType grantType = "client_credentials".equals(client.getAuthorizationGrantType()) ?
                AuthorizationGrantType.CLIENT_CREDENTIALS : AuthorizationGrantType.AUTHORIZATION_CODE;

        // Determine token format
        OAuth2TokenFormat tokenFormat = "reference".equals(client.getTokenFormat()) ?
                OAuth2TokenFormat.REFERENCE : OAuth2TokenFormat.SELF_CONTAINED;

        // Build the registered client with all settings in one pass
        return RegisteredClient.withId(client.getId())
                .clientId(client.getClientId())
                .clientName(client.getClientName())
                .clientSecret(passwordEncoder.encode(client.getClientSecret()))
                .redirectUri(client.getRedirectUri())
                .authorizationGrantType(grantType)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(tokenFormat)
                        .accessTokenTimeToLive(Duration.ofHours(12))
                        .build()
                )
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(client.isRequireProofKey())
                        .requireAuthorizationConsent(true)
                        .build())
                .scope("openid")
                .scope("read")
                .scope("write")
                .build();
    }
}