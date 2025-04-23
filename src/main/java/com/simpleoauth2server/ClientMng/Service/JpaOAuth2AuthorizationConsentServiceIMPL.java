package com.simpleoauth2server.ClientMng.Service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;


import com.simpleoauth2server.ClientMng.Entity.OAuth2AuthorizationConsentEntity;
import com.simpleoauth2server.ClientMng.Repo.OAuth2AuthorizationConsentRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class JpaOAuth2AuthorizationConsentServiceIMPL implements OAuth2AuthorizationConsentService {

    private final OAuth2AuthorizationConsentRepository repository;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void save(OAuth2AuthorizationConsent authorizationConsent) {
        OAuth2AuthorizationConsentEntity entity = toEntity(authorizationConsent);
        repository.save(entity);
    }

    @Override
    @Transactional
    public void remove(OAuth2AuthorizationConsent authorizationConsent) {
        OAuth2AuthorizationConsentEntity.AuthorizationConsentId id =
                new OAuth2AuthorizationConsentEntity.AuthorizationConsentId(
                        authorizationConsent.getRegisteredClientId(),
                        authorizationConsent.getPrincipalName());
        repository.deleteById(id);
    }

    @Override
    public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
        return repository.findById_RegisteredClientIdAndId_PrincipalName(registeredClientId, principalName)
                .map(this::toObject)
                .orElse(null);
    }

    private OAuth2AuthorizationConsent toObject(OAuth2AuthorizationConsentEntity entity) {
        final Set<GrantedAuthority> authorities = new HashSet<>();
        if (StringUtils.hasText(entity.getAuthorities())) {
            try {
                Set<String> authorityStrings = objectMapper.readValue(
                        entity.getAuthorities(), new TypeReference<Set<String>>() {});

                authorities.addAll(authorityStrings.stream()
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toSet()));
            } catch (Exception e) {
                throw new RuntimeException("Error deserializing authorities", e);
            }
        }

        return OAuth2AuthorizationConsent.withId(
                        entity.getId().getRegisteredClientId(),
                        entity.getId().getPrincipalName())
                .authorities(grantedAuthorities -> grantedAuthorities.addAll(authorities))
                .build();
    }

    private OAuth2AuthorizationConsentEntity toEntity(OAuth2AuthorizationConsent authorizationConsent) {
        OAuth2AuthorizationConsentEntity.AuthorizationConsentId id =
                new OAuth2AuthorizationConsentEntity.AuthorizationConsentId(
                        authorizationConsent.getRegisteredClientId(),
                        authorizationConsent.getPrincipalName());

        Set<String> authorities = authorizationConsent.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());

        String authoritiesJson;
        try {
            authoritiesJson = objectMapper.writeValueAsString(authorities);
        } catch (Exception e) {
            throw new RuntimeException("Error serializing authorities", e);
        }

        return new OAuth2AuthorizationConsentEntity(id, authoritiesJson);
    }
}