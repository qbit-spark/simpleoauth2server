package com.simpleoauth2server.ClientMng.Entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.Objects;

@Entity
@Table(name = "oauth2_authorization_consent")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class OAuth2AuthorizationConsentEntity {

    @EmbeddedId
    private AuthorizationConsentId id;

    @Column(name = "authorities", length = 1000)
    private String authorities;

    @Embeddable
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class AuthorizationConsentId implements Serializable {
        @Column(name = "registered_client_id")
        private String registeredClientId;

        @Column(name = "principal_name")
        private String principalName;

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            AuthorizationConsentId that = (AuthorizationConsentId) o;
            return Objects.equals(registeredClientId, that.registeredClientId) &&
                    Objects.equals(principalName, that.principalName);
        }

        @Override
        public int hashCode() {
            return Objects.hash(registeredClientId, principalName);
        }
    }
}