package com.simpleoauth2server.ClientMng.Service;


import com.simpleoauth2server.ClientMng.Entity.RegisteredClientEntity;
import com.simpleoauth2server.ClientMng.Repo.RegisteredClientEntityRepository;
import com.simpleoauth2server.ClientMng.dto.ClientRegistrationDTO;
import com.simpleoauth2server.ClientMng.dto.ClientResponseDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class ClientService {

    private final RegisteredClientRepository registeredClientRepository;
    private final RegisteredClientEntityRepository clientEntityRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public ClientResponseDTO registerClient(ClientRegistrationDTO registrationDTO) {
        // Generate client ID and secret
        String clientId = UUID.randomUUID().toString().substring(0, 8);
        String clientSecret = UUID.randomUUID().toString();

        // Convert grant types from strings to AuthorizationGrantType
        Set<AuthorizationGrantType> grantTypes = new HashSet<>();
        if (registrationDTO.getAuthorizationGrantTypes() != null) {
            grantTypes = registrationDTO.getAuthorizationGrantTypes().stream()
                    .map(AuthorizationGrantType::new)
                    .collect(Collectors.toSet());
        } else {
            // Default grant types
            grantTypes.add(AuthorizationGrantType.AUTHORIZATION_CODE);
            grantTypes.add(AuthorizationGrantType.REFRESH_TOKEN);
        }

        // Convert auth methods from strings to ClientAuthenticationMethod
        Set<ClientAuthenticationMethod> authMethods = new HashSet<>();
        if (registrationDTO.getClientAuthenticationMethods() != null) {
            authMethods = registrationDTO.getClientAuthenticationMethods().stream()
                    .map(ClientAuthenticationMethod::new)
                    .collect(Collectors.toSet());
        } else {
            // Default auth method
            authMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
        }

        // Build token settings
        TokenSettings.Builder tokenSettingsBuilder = TokenSettings.builder();
        if (registrationDTO.getAccessTokenTimeToLiveSeconds() != null) {
            tokenSettingsBuilder.accessTokenTimeToLive(Duration.ofSeconds(registrationDTO.getAccessTokenTimeToLiveSeconds()));
        }
        if (registrationDTO.getRefreshTokenTimeToLiveSeconds() != null) {
            tokenSettingsBuilder.refreshTokenTimeToLive(Duration.ofSeconds(registrationDTO.getRefreshTokenTimeToLiveSeconds()));
        }
        if (registrationDTO.getAuthorizationCodeTimeToLiveSeconds() != null) {
            tokenSettingsBuilder.authorizationCodeTimeToLive(Duration.ofSeconds(registrationDTO.getAuthorizationCodeTimeToLiveSeconds()));
        }
        if (registrationDTO.getDeviceCodeTimeToLiveSeconds() != null) {
            tokenSettingsBuilder.deviceCodeTimeToLive(Duration.ofSeconds(registrationDTO.getDeviceCodeTimeToLiveSeconds()));
        }
        if (registrationDTO.getReuseRefreshTokens() != null) {
            tokenSettingsBuilder.reuseRefreshTokens(registrationDTO.getReuseRefreshTokens());
        }

        // Create RegisteredClient
        RegisteredClient.Builder clientBuilder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientSecret(passwordEncoder.encode(clientSecret))
                .clientIdIssuedAt(Instant.now())
                .clientName(registrationDTO.getClientName());

        // Add authentication methods
        authMethods.forEach(clientBuilder::clientAuthenticationMethod);

        // Add grant types
        grantTypes.forEach(clientBuilder::authorizationGrantType);

        // Add redirect URIs and scopes
        if (registrationDTO.getRedirectUris() != null) {
            registrationDTO.getRedirectUris().forEach(clientBuilder::redirectUri);
        }

        if (registrationDTO.getScopes() != null) {
            registrationDTO.getScopes().forEach(clientBuilder::scope);
        }

        // Set client settings
        clientBuilder.clientSettings(ClientSettings.builder()
                .requireAuthorizationConsent(registrationDTO.isRequireAuthorizationConsent())
                .build());

        // Set token settings
        clientBuilder.tokenSettings(tokenSettingsBuilder.build());

        // Save the client
        RegisteredClient registeredClient = clientBuilder.build();
        registeredClientRepository.save(registeredClient);

        // Create response DTO with the generated credentials
        ClientResponseDTO responseDTO = new ClientResponseDTO();
        responseDTO.setId(registeredClient.getId());
        responseDTO.setClientId(clientId);
        responseDTO.setClientSecret(clientSecret); // Return in plain text for the registration response only
        responseDTO.setClientName(registrationDTO.getClientName());
        responseDTO.setRedirectUris(registrationDTO.getRedirectUris());
        responseDTO.setScopes(registrationDTO.getScopes());
        responseDTO.setAuthorizationGrantTypes(registrationDTO.getAuthorizationGrantTypes());
        responseDTO.setClientAuthenticationMethods(registrationDTO.getClientAuthenticationMethods());
        responseDTO.setClientIdIssuedAt(Instant.now());
        responseDTO.setAccessTokenTimeToLiveSeconds(registrationDTO.getAccessTokenTimeToLiveSeconds());
        responseDTO.setRefreshTokenTimeToLiveSeconds(registrationDTO.getRefreshTokenTimeToLiveSeconds());

        return responseDTO;
    }

    @Transactional(readOnly = true)
    public List<ClientResponseDTO> getAllClients() {
        return clientEntityRepository.findAll().stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public ClientResponseDTO getClientById(String id) {
        RegisteredClientEntity entity = clientEntityRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Client not found with id: " + id));
        return convertToDTO(entity);
    }

    @Transactional(readOnly = true)
    public ClientResponseDTO getClientByClientId(String clientId) {
        RegisteredClientEntity entity = clientEntityRepository.findByClientId(clientId)
                .orElseThrow(() -> new IllegalArgumentException("Client not found with clientId: " + clientId));
        return convertToDTO(entity);
    }

    private ClientResponseDTO convertToDTO(RegisteredClientEntity entity) {
        ClientResponseDTO dto = new ClientResponseDTO();
        dto.setId(entity.getId().toString());
        dto.setClientId(entity.getClientId());
        dto.setClientName(entity.getClientName());
        dto.setClientIdIssuedAt(entity.getClientIdIssuedAt());
        dto.setClientSecretExpiresAt(entity.getClientSecretExpiresAt());
        dto.setRedirectUris(entity.getRedirectUris());
        dto.setScopes(entity.getScopes());
        dto.setAuthorizationGrantTypes(entity.getAuthorizationGrantTypes());
        dto.setClientAuthenticationMethods(entity.getClientAuthenticationMethods());

        if (entity.getTokenSettingsEntity() != null) {
            dto.setAccessTokenTimeToLiveSeconds(entity.getTokenSettingsEntity().getAccessTokenTimeToLiveSeconds());
            dto.setRefreshTokenTimeToLiveSeconds(entity.getTokenSettingsEntity().getRefreshTokenTimeToLiveSeconds());
        }

        return dto;
    }
}