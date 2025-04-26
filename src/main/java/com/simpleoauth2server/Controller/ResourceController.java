package com.simpleoauth2server.Controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class ResourceController {

    @GetMapping("/public")
    public Map<String, String> publicEndpoint() {
        return Collections.singletonMap("message", "This is a public endpoint");
    }

    @GetMapping("/private")
    public Map<String, Object> privateEndpoint(@AuthenticationPrincipal Jwt jwt) {
        return Map.of(
                "message", "This is a private endpoint",
                "subject", jwt.getSubject(),
                "scopes", jwt.getClaimAsString("scope"),
                "issuer", jwt.getIssuer().toString()
        );
    }
}