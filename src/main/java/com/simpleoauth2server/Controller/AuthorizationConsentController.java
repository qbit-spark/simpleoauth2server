package com.simpleoauth2server.Controller;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Principal;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

@RequiredArgsConstructor
@Controller
public class AuthorizationConsentController {

    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationConsentService authorizationConsentService;

    @GetMapping("/oauth2/consent")
    public String consent(Principal principal, Model model,
                          @RequestParam(OAuth2ParameterNames.CLIENT_ID) String clientId,
                          @RequestParam(OAuth2ParameterNames.SCOPE) String scope,
                          @RequestParam(OAuth2ParameterNames.STATE) String state) {

        // Get client details
        RegisteredClient client = this.registeredClientRepository.findByClientId(clientId);
        if (client == null) {
            throw new IllegalArgumentException("Invalid client");
        }

        // Debug logging
        System.out.println("Client ID: " + clientId);
        System.out.println("Client object ID: " + client.getId());
        System.out.println("Client name: " + client.getClientName());
        System.out.println("Requested scopes: " + scope);

        // Get existing consent - use client.getId() for the lookup, not clientId
        OAuth2AuthorizationConsent consent = this.authorizationConsentService.findById(client.getId(), principal.getName());

        // Process scopes
        Set<String> scopesToApprove = new HashSet<>();
        Set<String> previouslyApprovedScopes = consent != null ? consent.getScopes() : Collections.emptySet();

        // Parse requested scopes
        for (String requestedScope : scope.split(" ")) {
            if (!previouslyApprovedScopes.contains(requestedScope)) {
                scopesToApprove.add(requestedScope);
            }
        }

        // Add attributes to model for the view
        model.addAttribute("clientId", clientId);  // This must be the original client ID
        model.addAttribute("clientName", client.getClientName() != null ? client.getClientName() : client.getClientId());
        model.addAttribute("state", state);
        model.addAttribute("scopes", scopesToApprove);
        model.addAttribute("previouslyApprovedScopes", previouslyApprovedScopes);

        return "consent";
    }
}