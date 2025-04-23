package com.simpleoauth2server.Controller;

import com.simpleoauth2server.ClientMng.Entity.CustomRegisteredClient;
import com.simpleoauth2server.ClientMng.Service.RegisteredClientRepositoryIMPL;
import com.simpleoauth2server.ClientMng.dto.ClientRegistrationDTO;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/clients")
@RequiredArgsConstructor
public class ClientController {

    private final RegisteredClientRepositoryIMPL clientService;


    /**
     * Register a new client for the authenticated user
     */
    @PostMapping
    public ResponseEntity<CustomRegisteredClient> registerClient(
            @Valid @RequestBody ClientRegistrationDTO registrationDTO) {

            CustomRegisteredClient client = clientService.registerClient(registrationDTO);
            return new ResponseEntity<>(client, HttpStatus.CREATED);

    }

    /**
     * Get all clients (admin only)
     */
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<CustomRegisteredClient>> getAllClients() {
        List<CustomRegisteredClient> clients = clientService.getAllClients();
        return new ResponseEntity<>(clients, HttpStatus.OK);
    }

}