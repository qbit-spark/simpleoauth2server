package com.simpleoauth2server.ClientMng.dto;

import lombok.Data;

import java.util.Set;

@Data
public class ClientRegistrationDTO {
    private String clientName;
    private Set<String> redirectUris;
    private Set<String> scopes;
    private Set<String> authorizationGrantTypes;
    private Set<String> clientAuthenticationMethods;
    private boolean requireAuthorizationConsent = true;

    // Token settings
    private Long accessTokenTimeToLiveSeconds = 1800L; // 30 minutes
    private Long refreshTokenTimeToLiveSeconds = 86400L; // 1 day
    private Long authorizationCodeTimeToLiveSeconds = 300L; // 5 minutes
    private Long deviceCodeTimeToLiveSeconds = 300L; // 5 minutes
    private Boolean reuseRefreshTokens = true;
}