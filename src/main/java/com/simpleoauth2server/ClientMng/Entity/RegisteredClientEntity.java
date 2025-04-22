package com.simpleoauth2server.ClientMng.Entity;

import com.simpleoauth2server.UserMng.Entity.User;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "oauth2_registered_clients")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class RegisteredClientEntity {

    @Id
    @GeneratedValue(generator = "UUID", strategy = GenerationType.AUTO)
    private UUID id;

    @Column(name = "oauth_client_id", unique = true, nullable = false)
    private String clientId;

    @Column(name = "client_secret")
    private String clientSecret;

    @Column(name = "client_id_issued_at")
    private Instant clientIdIssuedAt;

    @Column(name = "client_secret_expires_at")
    private Instant clientSecretExpiresAt;

    @Column(name = "client_name")
    private String clientName;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "oauth2_registered_client_auth_methods",
            joinColumns = @JoinColumn(name = "registered_client_id"))
    @Column(name = "auth_method")
    private Set<String> clientAuthenticationMethods;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "oauth2_registered_client_grant_types",
            joinColumns = @JoinColumn(name = "registered_client_id"))
    @Column(name = "grant_type")
    private Set<String> authorizationGrantTypes;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "oauth2_registered_client_redirect_uris",
            joinColumns = @JoinColumn(name = "registered_client_id"))
    @Column(name = "redirect_uri")
    private Set<String> redirectUris;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "oauth2_registered_client_scopes",
            joinColumns = @JoinColumn(name = "registered_client_id"))
    @Column(name = "scope")
    private Set<String> scopes;

    // Keep for backward compatibility
    @Column(name = "client_settings", length = 2000)
    private String clientSettings;

    // Keep for backward compatibility and non-duration settings
    @Column(name = "token_settings", length = 2000)
    private String tokenSettings;

    // One-to-one relationship with TokenSettingsEntity
    @OneToOne(cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.EAGER)
    @JoinColumn(name = "token_settings_id")
    private TokenSettingsEntity tokenSettingsEntity;

    // In RegisteredClientEntity.java
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User owner;
}