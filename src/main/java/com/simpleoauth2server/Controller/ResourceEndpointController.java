package com.simpleoauth2server.Controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/resource")
public class ResourceEndpointController {

    @GetMapping("/public")
    public Map<String, String> publicEndpoint() {
        return Collections.singletonMap("message", "This is a public endpoint from the resource server");
    }

    @GetMapping("/protected")
    public Map<String, Object> protectedEndpoint(@AuthenticationPrincipal Jwt jwt) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "This is a protected endpoint - requires 'read' scope");
        response.put("subject", jwt.getSubject());
        response.put("scopes", jwt.getClaimAsString("scope"));
        response.put("issuer", jwt.getIssuer().toString());
        response.put("tokenId", jwt.getId());

        // Include expiration information
        if (jwt.getExpiresAt() != null) {
            response.put("expiration", jwt.getExpiresAt().toString());
        }

        return response;
    }

    @GetMapping("/admin")
    public Map<String, Object> adminEndpoint(@AuthenticationPrincipal Jwt jwt) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Admin endpoint - requires authentication");
        response.put("tokenDetails", jwt.getClaims());

        return response;
    }
}