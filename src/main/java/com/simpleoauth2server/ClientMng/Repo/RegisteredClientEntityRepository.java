package com.simpleoauth2server.ClientMng.Repo;

import com.simpleoauth2server.ClientMng.Entity.CustomRegisteredClient;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface RegisteredClientEntityRepository extends JpaRepository<CustomRegisteredClient, UUID> {
    Optional<CustomRegisteredClient> findByClientId(String clientId);
    Optional<CustomRegisteredClient> findById(String id);
}