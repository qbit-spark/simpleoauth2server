package com.simpleoauth2server.ClientMng.Entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "registered_client")
@Getter
@Setter
@ToString
@AllArgsConstructor
@NoArgsConstructor
public class CustomRegisteredClient {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @Column(name = "client_id", unique = true, nullable = false)
    private String clientId;

    @Column(name = "client_name", nullable = false)
    private String clientName;

    @Column(name = "client_secret", nullable = false)
    private String clientSecret;

    @Column(name = "authorization_grant_type", nullable = false)
    private String authorizationGrantType;

    @Column(name = "redirect_uri", nullable = false)
    private String redirectUri;

    @Column(name = "require_proof_key", nullable = false)
    private boolean requireProofKey;

    @Column(name = "token_format", nullable = false)
    private String tokenFormat;

}