package com.simpleoauth2server.ClientMng.Entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Entity
@Table(name = "oauth2_token_settings")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class TokenSettingsEntity {

    @Id
    @GeneratedValue(generator = "UUID", strategy = GenerationType.AUTO)
    private UUID id;

    // Store durations as seconds (long values)
    @Column(name = "access_token_ttl_seconds")
    private Long accessTokenTimeToLiveSeconds;

    @Column(name = "refresh_token_ttl_seconds")
    private Long refreshTokenTimeToLiveSeconds;

    @Column(name = "authorization_code_ttl_seconds")
    private Long authorizationCodeTimeToLiveSeconds;

    @Column(name = "device_code_ttl_seconds")
    private Long deviceCodeTimeToLiveSeconds;

    @Column(name = "reuse_refresh_tokens")
    private Boolean reuseRefreshTokens = true;

    @Column(name = "id_token_signature_algorithm", length = 50)
    private String idTokenSignatureAlgorithm = "RS256";

    @Column(name = "access_token_format", length = 50)
    private String accessTokenFormat = "self-contained";

    @Column(name = "x509_certificate_bound_access_tokens")
    private Boolean x509CertificateBoundAccessTokens = false;

    // Bidirectional relationship with RegisteredClientEntity (optional)
    @OneToOne(mappedBy = "tokenSettingsEntity")
    private RegisteredClientEntity registeredClientEntity;

    // Factory method for creating an entity with default values
    public static TokenSettingsEntity createDefault() {
        TokenSettingsEntity entity = new TokenSettingsEntity();
        entity.setAccessTokenTimeToLiveSeconds(1800L);        // 30 minutes
        entity.setRefreshTokenTimeToLiveSeconds(86400L);      // 1 day
        entity.setAuthorizationCodeTimeToLiveSeconds(300L);   // 5 minutes
        entity.setDeviceCodeTimeToLiveSeconds(300L);          // 5 minutes
        entity.setReuseRefreshTokens(true);
        entity.setIdTokenSignatureAlgorithm("RS256");
        entity.setAccessTokenFormat("self-contained");
        entity.setX509CertificateBoundAccessTokens(false);
        return entity;
    }
}