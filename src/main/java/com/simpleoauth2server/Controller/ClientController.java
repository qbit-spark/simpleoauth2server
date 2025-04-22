package com.simpleoauth2server.Controller;

import com.simpleoauth2server.ClientMng.Service.ClientManagementService;
import com.simpleoauth2server.ClientMng.dto.ClientRegistrationDTO;
import com.simpleoauth2server.ClientMng.dto.ClientResponseDTO;
import com.simpleoauth2server.GlobeAdvice.Exceptions.RandomExceptions;
import com.simpleoauth2server.UserMng.Entity.User;
import com.simpleoauth2server.UserMng.Service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/clients")
@RequiredArgsConstructor
public class ClientController {

    private final ClientManagementService clientService;
    private final UserService userService;

    /**
     * Register a new client for the authenticated user
     */
    @PostMapping
    public ResponseEntity<ClientResponseDTO> registerClient(
            @Valid @RequestBody ClientRegistrationDTO registrationDTO,
            Authentication authentication) {

        try {
            User currentUser = getCurrentUser(authentication);
            ClientResponseDTO client = clientService.registerClient(registrationDTO, currentUser);
            return new ResponseEntity<>(client, HttpStatus.CREATED);
        } catch (Exception e) {
            throw e;
        }
    }

    /**
     * Get all clients owned by the current user
     */
    @GetMapping("/my-clients")
    public ResponseEntity<List<ClientResponseDTO>> getMyClients(Authentication authentication) {
        User currentUser = getCurrentUser(authentication);
        List<ClientResponseDTO> clients = clientService.getClientsByOwner(currentUser);
        return new ResponseEntity<>(clients, HttpStatus.OK);
    }

    /**
     * Get all clients (admin only)
     */
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<ClientResponseDTO>> getAllClients() {
        List<ClientResponseDTO> clients = clientService.getAllClients();
        return new ResponseEntity<>(clients, HttpStatus.OK);
    }

    /**
     * Get a single client by ID
     */
    @GetMapping("/{id}")
    public ResponseEntity<ClientResponseDTO> getClientById(
            @PathVariable UUID id,
            Authentication authentication) throws RandomExceptions {

        try {
            User currentUser = getCurrentUser(authentication);
            ClientResponseDTO client = clientService.getClientById(id, currentUser);
            return new ResponseEntity<>(client, HttpStatus.OK);
        } catch (RandomExceptions e) {
            throw e;
        }
    }

    /**
     * Get a client by client ID
     */
    @GetMapping("/client-id/{clientId}")
    public ResponseEntity<ClientResponseDTO> getClientByClientId(
            @PathVariable String clientId,
            Authentication authentication) throws RandomExceptions {

        try {
            User currentUser = getCurrentUser(authentication);
            ClientResponseDTO client = clientService.getClientByClientId(clientId, currentUser);
            return new ResponseEntity<>(client, HttpStatus.OK);
        } catch (RandomExceptions e) {
            throw e;
        }
    }

    /**
     * Reset a client secret
     */
    @PostMapping("/{id}/reset-secret")
    public ResponseEntity<ClientResponseDTO> resetClientSecret(
            @PathVariable UUID id,
            Authentication authentication) throws RandomExceptions {

        try {
            User currentUser = getCurrentUser(authentication);
            ClientResponseDTO client = clientService.resetClientSecret(id, currentUser);
            return new ResponseEntity<>(client, HttpStatus.OK);
        } catch (RandomExceptions e) {
            throw e;
        }
    }

    /**
     * Update a client
     */
    @PutMapping("/{id}")
    public ResponseEntity<ClientResponseDTO> updateClient(
            @PathVariable UUID id,
            @Valid @RequestBody ClientRegistrationDTO updateDTO,
            Authentication authentication) throws RandomExceptions {

        try {
            User currentUser = getCurrentUser(authentication);
            ClientResponseDTO client = clientService.updateClient(id, updateDTO, currentUser);
            return new ResponseEntity<>(client, HttpStatus.OK);
        } catch (RandomExceptions e) {
            throw e;
        }
    }

    /**
     * Delete a client
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteClient(
            @PathVariable UUID id,
            Authentication authentication) throws RandomExceptions {

        try {
            User currentUser = getCurrentUser(authentication);
            clientService.deleteClient(id, currentUser);
            return new ResponseEntity<>(HttpStatus.NO_CONTENT);
        } catch (RandomExceptions e) {
            throw e;
        }
    }

    /**
     * Helper method to get the current user from Authentication
     */
    private User getCurrentUser(Authentication authentication) {
        return userService.getUserPlainByUsername(authentication.getName());
    }
}