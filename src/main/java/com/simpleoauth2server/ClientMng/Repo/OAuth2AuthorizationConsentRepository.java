package com.simpleoauth2server.ClientMng.Repo;

import com.simpleoauth2server.ClientMng.Entity.OAuth2AuthorizationConsentEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface OAuth2AuthorizationConsentRepository extends
        JpaRepository<OAuth2AuthorizationConsentEntity, OAuth2AuthorizationConsentEntity.AuthorizationConsentId> {

    Optional<OAuth2AuthorizationConsentEntity> findById_RegisteredClientIdAndId_PrincipalName(
            String registeredClientId, String principalName);
}