package com.simpleoauth2server.ClientMng.Repo;

import com.simpleoauth2server.ClientMng.Entity.RegisteredClientEntity;
import com.simpleoauth2server.UserMng.Entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface RegisteredClientEntityRepository extends JpaRepository<RegisteredClientEntity, UUID> {
    Optional<RegisteredClientEntity> findByClientId(String clientId);
    List<RegisteredClientEntity> findByOwner(User owner);
    long countByTokenSettingsEntityIsNull();
    List<RegisteredClientEntity> findByTokenSettingsEntityIsNull();
}