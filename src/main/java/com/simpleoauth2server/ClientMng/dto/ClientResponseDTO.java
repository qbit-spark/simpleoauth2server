package com.simpleoauth2server.ClientMng.dto;

import lombok.Data;

import java.time.Instant;
import java.util.Set;

@Data
public class ClientResponseDTO {
    private String id;
    private String clientId;
    private String clientSecret;
    private String clientName;
    private Instant clientIdIssuedAt;
    private Instant clientSecretExpiresAt;
    private Set<String> redirectUris;
    private Set<String> scopes;
    private Set<String> authorizationGrantTypes;
    private Set<String> clientAuthenticationMethods;
    private Long accessTokenTimeToLiveSeconds;
    private Long refreshTokenTimeToLiveSeconds;
}