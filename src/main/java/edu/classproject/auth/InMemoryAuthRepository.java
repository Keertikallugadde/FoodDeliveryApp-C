package edu.classproject.auth;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class InMemoryAuthRepository implements AuthRepository {
    private final Map<String, AuthSession> storage = new HashMap<>();
    private final Map<String, String> passwordHashesByEmail = new HashMap<>();

    @Override
    public void save(AuthSession session) {
        storage.put(session.sessionId(), session);
    }

    @Override
    public Optional<AuthSession> findBySessionId(String sessionId) {
        return Optional.ofNullable(storage.get(sessionId));
    }

    @Override
    public void deleteBySessionId(String sessionId) {
        storage.remove(sessionId);
    }

    @Override
    public void savePasswordHash(String email, String passwordHash) {
        if (email == null || passwordHash == null) {
            throw new IllegalArgumentException("Email and password hash are required");
        }
        passwordHashesByEmail.put(normalizeEmail(email), passwordHash);
    }

    @Override
    public Optional<String> findPasswordHashByEmail(String email) {
        if (email == null || email.isBlank()) {
            return Optional.empty();
        }
        return Optional.ofNullable(passwordHashesByEmail.get(normalizeEmail(email)));
    }

    private String normalizeEmail(String email) {
        return email.trim().toLowerCase();
    }
}