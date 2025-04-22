package com.simpleoauth2server.ClientMng.Service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.simpleoauth2server.ClientMng.Entity.RegisteredClientEntity;
import com.simpleoauth2server.ClientMng.Entity.TokenSettingsEntity;
import com.simpleoauth2server.ClientMng.Repo.RegisteredClientEntityRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
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
import java.util.*;
import java.util.stream.Collectors;

@Service
@Primary
@Order(1)
@Transactional
public class DatabaseRegisteredClientRepository implements RegisteredClientRepository {

    private static final Logger logger = LoggerFactory.getLogger(DatabaseRegisteredClientRepository.class);
    private final RegisteredClientEntityRepository repository;
    private final ObjectMapper objectMapper;

    public DatabaseRegisteredClientRepository(
            RegisteredClientEntityRepository repository,
            ObjectMapper objectMapper) {
        this.repository = repository;
        this.objectMapper = objectMapper;
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        logger.debug("Saving client: {}", registeredClient.getClientId());
        RegisteredClientEntity entity = toEntity(registeredClient);
        repository.save(entity);
    }

    @Override
    public RegisteredClient findById(String id) {
        logger.debug("Finding client by ID: {}", id);

        // Try to find by UUID first if the ID is a valid UUID
        try {
            UUID uuid = UUID.fromString(id);
            return repository.findById(String.valueOf(uuid))
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
    public RegisteredClient findByClientId(String clientId) {
        logger.info("Finding client by clientId: {}", clientId);
        return repository.findByClientId(clientId)
                .map(this::toObject)
                .orElse(null);
    }

    // Modify only the toEntity method in DatabaseRegisteredClientRepository.java

    private RegisteredClientEntity toEntity(RegisteredClient registeredClient) {
        RegisteredClientEntity entity = new RegisteredClientEntity();

        // For new clients, we don't set ID as it will be auto-generated
        // For existing clients that might have been fetched from DB previously
        try {
            if (registeredClient.getId() != null) {
                // If it's a valid UUID, use it
                UUID.fromString(registeredClient.getId());
                entity.setId(UUID.fromString(registeredClient.getId()));
            }
        } catch (IllegalArgumentException e) {
            // Not a valid UUID - it's likely a business identifier, we'll let JPA generate a new UUID
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
            tokenSettingsEntity.setRegisteredClientEntity(entity); // This is the key fix

        } catch (JsonProcessingException e) {
            logger.error("Error serializing settings for client {}: {}",
                    registeredClient.getClientId(), e.getMessage());
            throw new RuntimeException("Error serializing settings", e);
        }

        return entity;
    }
    /**
     * Converts a RegisteredClientEntity from the database to a RegisteredClient object.
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
     * Safely deserializes JSON settings strings to maps.
     */
    private Map<String, Object> deserializeSettings(String settingsJson) {
        try {
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