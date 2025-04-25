package com.simpleoauth2server.Controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/token")
public class TokenDebugController {

    @GetMapping("/debug")
    public ResponseEntity<Map<String, Object>> debugToken(HttpServletRequest request) {
        String token = extractTokenFromRequest(request);
        Map<String, Object> response = new HashMap<>();

        if (token == null) {
            response.put("error", "No token provided");
            return ResponseEntity.badRequest().body(response);
        }

        try {
            // Decode token parts without verification
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                response.put("error", "Invalid JWT format");
                return ResponseEntity.badRequest().body(response);
            }

            // Decode header
            String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]));
            response.put("header", new ObjectMapper().readTree(headerJson));

            // Decode payload
            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]));
            response.put("payload", new ObjectMapper().readTree(payloadJson));

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            response.put("error", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    private String extractTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}