package com.simpleoauth2server.ClientMng.Repo;

import com.simpleoauth2server.ClientMng.Entity.RegisteredClientEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RegisteredClientEntityRepository extends JpaRepository<RegisteredClientEntity, String> {
    Optional<RegisteredClientEntity> findByClientId(String clientId);
}