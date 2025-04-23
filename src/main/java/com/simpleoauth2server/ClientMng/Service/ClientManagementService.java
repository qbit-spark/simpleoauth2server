package com.simpleoauth2server.ClientMng.Service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.simpleoauth2server.ClientMng.Entity.RegisteredClientEntity;
import com.simpleoauth2server.ClientMng.Entity.TokenSettingsEntity;
import com.simpleoauth2server.ClientMng.Repo.RegisteredClientEntityRepository;
import com.simpleoauth2server.ClientMng.dto.ClientRegistrationDTO;
import com.simpleoauth2server.ClientMng.dto.ClientResponseDTO;
import com.simpleoauth2server.GlobeAdvice.Exceptions.RandomExceptions;
import com.simpleoauth2server.UserMng.Entity.User;

import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.RandomStringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Primary;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Service
@Primary
@RequiredArgsConstructor
public class ClientManagementService implements RegisteredClientRepository {

    private static final Logger logger = LoggerFactory.getLogger(ClientManagementService.class);

    private final RegisteredClientEntityRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final ObjectMapper objectMapper;

    // ===== Client Management API methods (for UI/API usage) =====

    /**
     * Register a new OAuth client for the authenticated user
     */
    @Transactional
    public ClientResponseDTO registerClient(ClientRegistrationDTO registrationDTO, User owner) {
        // Generate client ID with a format like "clt_xxxxxxxx"
        String clientId = "clt_" + RandomStringUtils.randomAlphanumeric(8);

        // Generate a more complex client secret
        String clientSecret = RandomStringUtils.randomAlphanumeric(70);
        String encodedSecret = passwordEncoder.encode(clientSecret);

        // Create a new client entity
        RegisteredClientEntity clientEntity = new RegisteredClientEntity();
        clientEntity.setId(UUID.randomUUID());
        clientEntity.setClientId(clientId);
        clientEntity.setClientSecret(encodedSecret);
        clientEntity.setClientName(registrationDTO.getClientName());
        clientEntity.setClientIdIssuedAt(Instant.now());

        // Set collections
        clientEntity.setRedirectUris(new HashSet<>(registrationDTO.getRedirectUris()));
        clientEntity.setScopes(new HashSet<>(registrationDTO.getScopes()));

        // Set grant types
        Set<String> grantTypes = new HashSet<>();
        if (registrationDTO.getAuthorizationGrantTypes() != null && !registrationDTO.getAuthorizationGrantTypes().isEmpty()) {
            grantTypes.addAll(registrationDTO.getAuthorizationGrantTypes());
        } else {
            grantTypes.add(AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
            grantTypes.add(AuthorizationGrantType.REFRESH_TOKEN.getValue());
        }
        clientEntity.setAuthorizationGrantTypes(grantTypes);

        // Set authentication methods
        Set<String> authMethods = new HashSet<>();
        if (registrationDTO.getClientAuthenticationMethods() != null && !registrationDTO.getClientAuthenticationMethods().isEmpty()) {
            authMethods.addAll(registrationDTO.getClientAuthenticationMethods());
        } else {
            authMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue());
        }
        clientEntity.setClientAuthenticationMethods(authMethods);

        // Create and set token settings
        TokenSettingsEntity tokenSettings = new TokenSettingsEntity();
        tokenSettings.setAccessTokenTimeToLiveSeconds(registrationDTO.getAccessTokenTimeToLiveSeconds());
        tokenSettings.setRefreshTokenTimeToLiveSeconds(registrationDTO.getRefreshTokenTimeToLiveSeconds());
        tokenSettings.setAuthorizationCodeTimeToLiveSeconds(registrationDTO.getAuthorizationCodeTimeToLiveSeconds());
        tokenSettings.setDeviceCodeTimeToLiveSeconds(registrationDTO.getDeviceCodeTimeToLiveSeconds());
        tokenSettings.setReuseRefreshTokens(registrationDTO.getReuseRefreshTokens());

        // Set up bidirectional relationship
        clientEntity.setTokenSettingsEntity(tokenSettings);
        tokenSettings.setRegisteredClientEntity(clientEntity);

        // Set the owner
        clientEntity.setOwner(owner);

        // Save the entity
        repository.saveAndFlush(clientEntity);

        // Create response DTO with the generated credentials
        ClientResponseDTO responseDTO = new ClientResponseDTO();
        responseDTO.setId(clientEntity.getId().toString());
        responseDTO.setClientId(clientId);
        responseDTO.setClientSecret(formatSecretForDisplay(clientSecret));
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

    /**
     * Get all clients belonging to the current user
     */
    @Transactional(readOnly = true)
    public List<ClientResponseDTO> getClientsByOwner(User owner) {
        return repository.findByOwner(owner).stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }

    /**
     * Get all clients (admin only)
     */
    @Transactional(readOnly = true)
    public List<ClientResponseDTO> getAllClients() {
        return repository.findAll().stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }

    /**
     * Get a specific client by ID
     */
    @Transactional(readOnly = true)
    public ClientResponseDTO getClientById(UUID id, User currentUser) throws RandomExceptions {
        RegisteredClientEntity entity = repository.findById(id)
                .orElseThrow(() -> new RandomExceptions("Client not found with id: " + id));

        // Verify ownership or admin access
        verifyOwnership(entity, currentUser);

        return convertToDTO(entity);
    }

    /**
     * Get a client by client ID
     */
    @Transactional(readOnly = true)
    public ClientResponseDTO getClientByClientId(String clientId, User currentUser) throws RandomExceptions {
        RegisteredClientEntity entity = repository.findByClientId(clientId)
                .orElseThrow(() -> new RandomExceptions("Client not found with clientId: " + clientId));

        // Verify ownership or admin access
        verifyOwnership(entity, currentUser);

        return convertToDTO(entity);
    }

    /**
     * Reset client secret
     */
    @Transactional
    public ClientResponseDTO resetClientSecret(UUID id, User currentUser) throws RandomExceptions {
        RegisteredClientEntity entity = repository.findById(id)
                .orElseThrow(() -> new RandomExceptions("Client not found with id: " + id));

        // Verify ownership or admin access
        verifyOwnership(entity, currentUser);

        // Generate a new client secret
        String newSecret = generateSecretKey();

        // Update the entity with the new hashed secret
        entity.setClientSecret(passwordEncoder.encode(newSecret));
        repository.save(entity);

        // Create response with the new secret
        ClientResponseDTO responseDTO = convertToDTO(entity);
        responseDTO.setClientSecret(formatSecretForDisplay(newSecret));

        return responseDTO;
    }

    /**
     * Delete a client
     */
    @Transactional
    public void deleteClient(UUID id, User currentUser) throws RandomExceptions {
        RegisteredClientEntity entity = repository.findById(id)
                .orElseThrow(() -> new RandomExceptions("Client not found with id: " + id));

        // Verify ownership or admin access
        verifyOwnership(entity, currentUser);

        // Delete the client
        repository.delete(entity);
    }

    /**
     * Update a client
     */
    @Transactional
    public ClientResponseDTO updateClient(UUID id, ClientRegistrationDTO updateDTO, User currentUser) throws RandomExceptions {
        RegisteredClientEntity entity = repository.findById(id)
                .orElseThrow(() -> new RandomExceptions("Client not found with id: " + id));

        // Verify ownership or admin access
        verifyOwnership(entity, currentUser);

        // Update basic properties
        if (updateDTO.getClientName() != null) {
            entity.setClientName(updateDTO.getClientName());
        }

        // Update redirect URIs if provided
        if (updateDTO.getRedirectUris() != null) {
            entity.setRedirectUris(new HashSet<>(updateDTO.getRedirectUris()));
        }

        // Update scopes if provided
        if (updateDTO.getScopes() != null) {
            entity.setScopes(new HashSet<>(updateDTO.getScopes()));
        }

        // Update authorization grant types if provided
        if (updateDTO.getAuthorizationGrantTypes() != null) {
            entity.setAuthorizationGrantTypes(new HashSet<>(updateDTO.getAuthorizationGrantTypes()));
        }

        // Update client authentication methods if provided
        if (updateDTO.getClientAuthenticationMethods() != null) {
            entity.setClientAuthenticationMethods(new HashSet<>(updateDTO.getClientAuthenticationMethods()));
        }

        // Update token settings if provided
        TokenSettingsEntity tokenSettings = entity.getTokenSettingsEntity();
        if (tokenSettings == null) {
            tokenSettings = TokenSettingsEntity.createDefault();
            entity.setTokenSettingsEntity(tokenSettings);
            tokenSettings.setRegisteredClientEntity(entity);
        }

        if (updateDTO.getAccessTokenTimeToLiveSeconds() != null) {
            tokenSettings.setAccessTokenTimeToLiveSeconds(updateDTO.getAccessTokenTimeToLiveSeconds());
        }

        if (updateDTO.getRefreshTokenTimeToLiveSeconds() != null) {
            tokenSettings.setRefreshTokenTimeToLiveSeconds(updateDTO.getRefreshTokenTimeToLiveSeconds());
        }

        if (updateDTO.getAuthorizationCodeTimeToLiveSeconds() != null) {
            tokenSettings.setAuthorizationCodeTimeToLiveSeconds(updateDTO.getAuthorizationCodeTimeToLiveSeconds());
        }

        if (updateDTO.getDeviceCodeTimeToLiveSeconds() != null) {
            tokenSettings.setDeviceCodeTimeToLiveSeconds(updateDTO.getDeviceCodeTimeToLiveSeconds());
        }

        if (updateDTO.getReuseRefreshTokens() != null) {
            tokenSettings.setReuseRefreshTokens(updateDTO.getReuseRefreshTokens());
        }

        // Save the updated entity
        repository.save(entity);

        return convertToDTO(entity);
    }

    // ===== Spring OAuth2 RegisteredClientRepository implementation =====

    @Override
    @Transactional
    public void save(RegisteredClient registeredClient) {
       //This method is not used in the current implementation
      // Ignore it plz
    }

    @Override
    @Transactional(readOnly = true)
    public RegisteredClient findById(String id) {
        logger.debug("Finding client by ID: {}", id);

        // Try to find by UUID first if the ID is a valid UUID
        try {
            UUID uuid = UUID.fromString(id);
            return repository.findById(uuid)
                    .map(this::toObject)
                    .orElse(null);
        } catch (IllegalArgumentException e) {
            // If not a valid UUID, try to find by client ID
            return repository.findByClientId(id)
                    .map(this::toObject)
                    .orElse(null);
        }
    }

    @Override
    @Transactional(readOnly = true)
    public RegisteredClient findByClientId(String clientId) {
        logger.info("Finding client by clientId: {}", clientId);
        return repository.findByClientId(clientId)
                .map(this::toObject)
                .orElse(null);
    }

    // ===== Helper methods =====

    /**
     * Convert a registered client entity to a response DTO
     */
    private ClientResponseDTO convertToDTO(RegisteredClientEntity entity) {
        ClientResponseDTO dto = new ClientResponseDTO();
        dto.setId(entity.getId().toString());
        dto.setClientId(entity.getClientId());
        // Do not include client secret in normal responses
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

    /**
     * Convert RegisteredClient to RegisteredClientEntity
     */
    private RegisteredClientEntity toEntity(RegisteredClient registeredClient) {
        RegisteredClientEntity entity = new RegisteredClientEntity();

        try {
            if (registeredClient.getId() != null) {
                entity.setId(UUID.fromString(registeredClient.getId()));
            } else {
                entity.setId(UUID.randomUUID());
            }
        } catch (IllegalArgumentException e) {
            // Not a valid UUID - we'll generate a new one
            entity.setId(UUID.randomUUID());
        }

        entity.setClientId(registeredClient.getClientId());
        entity.setClientSecret(registeredClient.getClientSecret());
        entity.setClientIdIssuedAt(registeredClient.getClientIdIssuedAt());
        entity.setClientSecretExpiresAt(registeredClient.getClientSecretExpiresAt());
        entity.setClientName(registeredClient.getClientName());

        entity.setClientAuthenticationMethods(
                registeredClient.getClientAuthenticationMethods().stream()
                        .map(ClientAuthenticationMethod::getValue)
                        .collect(Collectors.toSet())
        );

        entity.setAuthorizationGrantTypes(
                registeredClient.getAuthorizationGrantTypes().stream()
                        .map(AuthorizationGrantType::getValue)
                        .collect(Collectors.toSet())
        );

        entity.setRedirectUris(new HashSet<>(registeredClient.getRedirectUris()));
        entity.setScopes(new HashSet<>(registeredClient.getScopes()));

        try {
            // Serialize client settings
            entity.setClientSettings(objectMapper.writeValueAsString(registeredClient.getClientSettings().getSettings()));

            // Serialize token settings (for backward compatibility)
            entity.setTokenSettings(objectMapper.writeValueAsString(registeredClient.getTokenSettings().getSettings()));

            // Create and populate TokenSettingsEntity
            TokenSettingsEntity tokenSettingsEntity = new TokenSettingsEntity();

            // Convert Duration values to seconds
            if (registeredClient.getTokenSettings().getAccessTokenTimeToLive() != null) {
                tokenSettingsEntity.setAccessTokenTimeToLiveSeconds(
                        registeredClient.getTokenSettings().getAccessTokenTimeToLive().getSeconds());
            }

            if (registeredClient.getTokenSettings().getRefreshTokenTimeToLive() != null) {
                tokenSettingsEntity.setRefreshTokenTimeToLiveSeconds(
                        registeredClient.getTokenSettings().getRefreshTokenTimeToLive().getSeconds());
            }

            if (registeredClient.getTokenSettings().getAuthorizationCodeTimeToLive() != null) {
                tokenSettingsEntity.setAuthorizationCodeTimeToLiveSeconds(
                        registeredClient.getTokenSettings().getAuthorizationCodeTimeToLive().getSeconds());
            }

            if (registeredClient.getTokenSettings().getDeviceCodeTimeToLive() != null) {
                tokenSettingsEntity.setDeviceCodeTimeToLiveSeconds(
                        registeredClient.getTokenSettings().getDeviceCodeTimeToLive().getSeconds());
            }

            tokenSettingsEntity.setReuseRefreshTokens(
                    registeredClient.getTokenSettings().isReuseRefreshTokens());

            if (registeredClient.getTokenSettings().getIdTokenSignatureAlgorithm() != null) {
                tokenSettingsEntity.setIdTokenSignatureAlgorithm(
                        registeredClient.getTokenSettings().getIdTokenSignatureAlgorithm().getName());
            }

            if (registeredClient.getTokenSettings().getAccessTokenFormat() != null) {
                tokenSettingsEntity.setAccessTokenFormat(
                        registeredClient.getTokenSettings().getAccessTokenFormat().getValue());
            }

            tokenSettingsEntity.setX509CertificateBoundAccessTokens(
                    registeredClient.getTokenSettings().isX509CertificateBoundAccessTokens());

            // Set the entity reference to establish the bidirectional relationship
            entity.setTokenSettingsEntity(tokenSettingsEntity);
            tokenSettingsEntity.setRegisteredClientEntity(entity);

        } catch (JsonProcessingException e) {
            logger.error("Error serializing settings for client {}: {}",
                    registeredClient.getClientId(), e.getMessage());
            throw new RuntimeException("Error serializing settings", e);
        }

        return entity;
    }

    /**
     * Convert RegisteredClientEntity to RegisteredClient
     */
    private RegisteredClient toObject(RegisteredClientEntity entity) {
        try {
            Set<ClientAuthenticationMethod> clientAuthenticationMethods = entity.getClientAuthenticationMethods().stream()
                    .map(ClientAuthenticationMethod::new)
                    .collect(Collectors.toSet());

            Set<AuthorizationGrantType> authorizationGrantTypes = entity.getAuthorizationGrantTypes().stream()
                    .map(AuthorizationGrantType::new)
                    .collect(Collectors.toSet());

            // Use the entity's UUID as the client ID for Spring OAuth2
            RegisteredClient.Builder builder = RegisteredClient.withId(entity.getId().toString())
                    .clientId(entity.getClientId())
                    .clientSecret(entity.getClientSecret())
                    .clientIdIssuedAt(entity.getClientIdIssuedAt())
                    .clientSecretExpiresAt(entity.getClientSecretExpiresAt())
                    .clientName(entity.getClientName());

            clientAuthenticationMethods.forEach(builder::clientAuthenticationMethod);
            authorizationGrantTypes.forEach(builder::authorizationGrantType);
            entity.getRedirectUris().forEach(builder::redirectUri);
            entity.getScopes().forEach(builder::scope);

            // Handle client settings
            Map<String, Object> clientSettingsMap = deserializeSettings(entity.getClientSettings());
            builder.clientSettings(ClientSettings.withSettings(clientSettingsMap).build());

            // Use TokenSettingsEntity if available
            if (entity.getTokenSettingsEntity() != null) {
                TokenSettingsEntity tokenEntity = entity.getTokenSettingsEntity();
                TokenSettings.Builder tokenBuilder = TokenSettings.builder();

                // Convert seconds back to Duration objects
                if (tokenEntity.getAccessTokenTimeToLiveSeconds() != null) {
                    tokenBuilder.accessTokenTimeToLive(
                            Duration.ofSeconds(tokenEntity.getAccessTokenTimeToLiveSeconds()));
                }

                if (tokenEntity.getRefreshTokenTimeToLiveSeconds() != null) {
                    tokenBuilder.refreshTokenTimeToLive(
                            Duration.ofSeconds(tokenEntity.getRefreshTokenTimeToLiveSeconds()));
                }

                if (tokenEntity.getAuthorizationCodeTimeToLiveSeconds() != null) {
                    tokenBuilder.authorizationCodeTimeToLive(
                            Duration.ofSeconds(tokenEntity.getAuthorizationCodeTimeToLiveSeconds()));
                }

                if (tokenEntity.getDeviceCodeTimeToLiveSeconds() != null) {
                    tokenBuilder.deviceCodeTimeToLive(
                            Duration.ofSeconds(tokenEntity.getDeviceCodeTimeToLiveSeconds()));
                }

                // Set other token properties
                if (tokenEntity.getReuseRefreshTokens() != null) {
                    tokenBuilder.reuseRefreshTokens(tokenEntity.getReuseRefreshTokens());
                }

                if (tokenEntity.getIdTokenSignatureAlgorithm() != null) {
                    tokenBuilder.idTokenSignatureAlgorithm(
                            SignatureAlgorithm.from(tokenEntity.getIdTokenSignatureAlgorithm()));
                }

                if (tokenEntity.getAccessTokenFormat() != null) {
                    tokenBuilder.accessTokenFormat(new OAuth2TokenFormat(tokenEntity.getAccessTokenFormat()));
                }

                if (tokenEntity.getX509CertificateBoundAccessTokens() != null) {
                    tokenBuilder.x509CertificateBoundAccessTokens(
                            tokenEntity.getX509CertificateBoundAccessTokens());
                }

                builder.tokenSettings(tokenBuilder.build());
            } else {
                // Fall back to JSON token settings if needed
                Map<String, Object> tokenSettingsMap = deserializeSettings(entity.getTokenSettings());
                tokenSettingsMap = ensureDurationFields(tokenSettingsMap);
                builder.tokenSettings(TokenSettings.withSettings(tokenSettingsMap).build());
            }

            return builder.build();
        } catch (Exception e) {
            logger.error("Error converting entity to RegisteredClient: {}", e.getMessage(), e);
            // Return a client with default token settings as fallback
            return createClientWithDefaultSettings(entity);
        }
    }

    /**
     * Generate a secure client secret
     */
    private String generateSecretKey() {
        // Generate a secret with a mix of characters
        return RandomStringUtils.randomAlphanumeric(200);
    }

    /**
     * Format a secret for display (mask part of it)
     */
    private String formatSecretForDisplay(String secret) {
        if (secret.length() <= 8) {
            return secret;
        }

        // Show first 4 and last 4 characters, hide the rest
        return secret.substring(0, 4) + "..." + secret.substring(secret.length() - 4);
    }

    /**
     * Verify that the current user is either the owner of the client or an admin
     */
    private void verifyOwnership(RegisteredClientEntity client, User currentUser) throws RandomExceptions {
        boolean isOwner = client.getOwner() != null && client.getOwner().getId().equals(currentUser.getId());
        boolean isAdmin = currentUser.getRoles().contains("ADMIN");

        if (!isOwner && !isAdmin) {
            throw new RandomExceptions("You don't have permission to access this client");
        }
    }

    /**
     * Safely deserializes JSON settings strings to maps.
     */
    private Map<String, Object> deserializeSettings(String settingsJson) {
        try {
            if (settingsJson == null || settingsJson.isEmpty()) {
                return new HashMap<>();
            }
            return objectMapper.readValue(settingsJson, new TypeReference<Map<String, Object>>() {});
        } catch (Exception e) {
            logger.warn("Error deserializing settings: {}", e.getMessage());
            return new HashMap<>();
        }
    }

    /**
     * Ensures all duration fields in token settings are properly converted to Duration objects.
     */
    private Map<String, Object> ensureDurationFields(Map<String, Object> tokenSettings) {
        Map<String, Object> converted = new HashMap<>(tokenSettings);
        Map<String, Duration> defaultDurations = getDefaultDurations();

        for (Map.Entry<String, Duration> entry : defaultDurations.entrySet()) {
            String field = entry.getKey();
            Duration defaultValue = entry.getValue();

            if (!converted.containsKey(field)) {
                logger.debug("Field {} missing from token settings, using default", field);
                converted.put(field, defaultValue);
                continue;
            }

            Object value = converted.get(field);
            if (value instanceof Duration) {
                // Already a Duration object, no conversion needed
                continue;
            }

            try {
                if (value instanceof Number) {
                    converted.put(field, Duration.ofSeconds(((Number) value).longValue()));
                    logger.debug("Converted numeric value for field {}", field);
                } else if (value instanceof String) {
                    String strValue = (String) value;
                    if (strValue.startsWith("PT") || strValue.startsWith("P")) {
                        converted.put(field, Duration.parse(strValue));
                        logger.debug("Parsed ISO-8601 duration for field {}: {}", field, strValue);
                    } else {
                        converted.put(field, Duration.ofSeconds(Long.parseLong(strValue)));
                        logger.debug("Converted string seconds for field {}: {}", field, strValue);
                    }
                } else {
                    logger.warn("Unexpected type for duration field {}: {}", field,
                            value != null ? value.getClass().getName() : "null");
                    converted.put(field, defaultValue);
                }
            } catch (Exception e) {
                logger.warn("Error converting duration for field {}: {}", field, e.getMessage());
                converted.put(field, defaultValue);
            }
        }

        return converted;
    }

    /**
     * Returns a map of default durations for token settings.
     */
    private Map<String, Duration> getDefaultDurations() {
        Map<String, Duration> defaults = new HashMap<>();
        defaults.put("access-token-time-to-live", Duration.ofMinutes(30));
        defaults.put("refresh-token-time-to-live", Duration.ofDays(1));
        defaults.put("authorization-code-time-to-live", Duration.ofMinutes(5));
        defaults.put("device-code-time-to-live", Duration.ofMinutes(5));
        return defaults;
    }

    /**
     * Creates a client with default settings as a fallback when conversion fails.
     */
    private RegisteredClient createClientWithDefaultSettings(RegisteredClientEntity entity) {
        logger.info("Creating fallback client with default settings for: {}", entity.getClientId());

        RegisteredClient.Builder builder = RegisteredClient.withId(entity.getId().toString())
                .clientId(entity.getClientId())
                .clientSecret(entity.getClientSecret());

        // Add auth methods (or use defaults if empty)
        if (entity.getClientAuthenticationMethods() != null && !entity.getClientAuthenticationMethods().isEmpty()) {
            entity.getClientAuthenticationMethods().stream()
                    .map(ClientAuthenticationMethod::new)
                    .forEach(builder::clientAuthenticationMethod);
        } else {
            builder.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
        }

        // Add grant types (or use defaults if empty)
        if (entity.getAuthorizationGrantTypes() != null && !entity.getAuthorizationGrantTypes().isEmpty()) {
            entity.getAuthorizationGrantTypes().stream()
                    .map(AuthorizationGrantType::new)
                    .forEach(builder::authorizationGrantType);
        } else {
            builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
        }

        // Add redirect URIs and scopes
        if (entity.getRedirectUris() != null) {
            entity.getRedirectUris().forEach(builder::redirectUri);
        }

        if (entity.getScopes() != null) {
            entity.getScopes().forEach(builder::scope);
        }

        // Apply default settings
        builder.clientSettings(ClientSettings.builder()
                .requireAuthorizationConsent(true)
                .build());

        builder.tokenSettings(TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofMinutes(30))
                .refreshTokenTimeToLive(Duration.ofDays(1))
                .authorizationCodeTimeToLive(Duration.ofMinutes(5))
                .build());

        return builder.build();
    }
}