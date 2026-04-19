package edu.classproject.auth;

import java.util.Optional;

public interface AuthRepository {
    void save(AuthSession session);

    Optional<AuthSession> findBySessionId(String sessionId);

    void deleteBySessionId(String sessionId);

    void savePasswordHash(String email, String passwordHash);

    Optional<String> findPasswordHashByEmail(String email);
}