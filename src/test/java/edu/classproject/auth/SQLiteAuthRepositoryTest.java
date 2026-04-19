package edu.classproject.auth;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SQLiteAuthRepositoryTest {
    @TempDir
    Path tempDir;

    @Test
    void saveAndFindBySessionId_shouldRoundTripSession() {
        String databaseUrl = "jdbc:sqlite:" + tempDir.resolve("auth-roundtrip.db");

        try (SQLiteAuthRepository repository = new SQLiteAuthRepository(databaseUrl)) {
            AuthSession session = new AuthSession(
                    "SES-123",
                    "USR-123",
                    Instant.parse("2026-04-19T10:00:00Z"),
                    Instant.parse("2026-04-19T11:00:00Z")
            );

            repository.save(session);

            AuthSession found = repository.findBySessionId("SES-123").orElseThrow();
            assertEquals(session, found);
        }
    }

    @Test
    void deleteBySessionId_shouldRemoveSession() {
        String databaseUrl = "jdbc:sqlite:" + tempDir.resolve("auth-delete.db");

        try (SQLiteAuthRepository repository = new SQLiteAuthRepository(databaseUrl)) {
            repository.save(new AuthSession(
                    "SES-DEL",
                    "USR-DEL",
                    Instant.parse("2026-04-19T10:00:00Z"),
                    Instant.parse("2026-04-19T10:30:00Z")
            ));
            assertTrue(repository.findBySessionId("SES-DEL").isPresent());

            repository.deleteBySessionId("SES-DEL");

            assertFalse(repository.findBySessionId("SES-DEL").isPresent());
        }
    }

    @Test
    void saveAndFindPasswordHashByEmail_shouldNormalizeAndRoundTrip() {
        String databaseUrl = "jdbc:sqlite:" + tempDir.resolve("auth-credentials.db");

        try (SQLiteAuthRepository repository = new SQLiteAuthRepository(databaseUrl)) {
            repository.savePasswordHash("Alex@Example.edu", "hash-1");

            String found = repository.findPasswordHashByEmail("alex@example.edu").orElseThrow();
            assertEquals("hash-1", found);
        }
    }
}