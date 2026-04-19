package edu.classproject.auth;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.Optional;

public class SQLiteAuthRepository implements AuthRepository, AutoCloseable {
    private final Connection connection;

    public SQLiteAuthRepository(String databaseUrl) {
        try {
            this.connection = DriverManager.getConnection(databaseUrl);
            initializeSchema();
        } catch (SQLException exception) {
            throw new IllegalStateException("Unable to initialize SQLite auth repository", exception);
        }
    }

    @Override
    public void save(AuthSession session) {
        String sql = """
                INSERT INTO auth_sessions(session_id, user_id, issued_at_epoch_ms, expires_at_epoch_ms)
                VALUES(?, ?, ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                user_id = excluded.user_id,
                issued_at_epoch_ms = excluded.issued_at_epoch_ms,
                expires_at_epoch_ms = excluded.expires_at_epoch_ms
                """;

        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, session.sessionId());
            statement.setString(2, session.userId());
            statement.setLong(3, session.issuedAt().toEpochMilli());
            statement.setLong(4, session.expiresAt().toEpochMilli());
            statement.executeUpdate();
        } catch (SQLException exception) {
            throw new IllegalStateException("Unable to save auth session", exception);
        }
    }

    @Override
    public Optional<AuthSession> findBySessionId(String sessionId) {
        String sql = "SELECT session_id, user_id, issued_at_epoch_ms, expires_at_epoch_ms FROM auth_sessions WHERE session_id = ?";

        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, sessionId);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (!resultSet.next()) {
                    return Optional.empty();
                }

                return Optional.of(new AuthSession(
                        resultSet.getString("session_id"),
                        resultSet.getString("user_id"),
                        Instant.ofEpochMilli(resultSet.getLong("issued_at_epoch_ms")),
                        Instant.ofEpochMilli(resultSet.getLong("expires_at_epoch_ms"))
                ));
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("Unable to find auth session", exception);
        }
    }

    @Override
    public void deleteBySessionId(String sessionId) {
        String sql = "DELETE FROM auth_sessions WHERE session_id = ?";

        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, sessionId);
            statement.executeUpdate();
        } catch (SQLException exception) {
            throw new IllegalStateException("Unable to delete auth session", exception);
        }
    }

    @Override
    public void savePasswordHash(String email, String passwordHash) {
        String sql = """
                INSERT INTO auth_credentials(email, password_hash)
                VALUES(?, ?)
                ON CONFLICT(email) DO UPDATE SET
                password_hash = excluded.password_hash
                """;

        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, normalizeEmail(email));
            statement.setString(2, passwordHash);
            statement.executeUpdate();
        } catch (SQLException exception) {
            throw new IllegalStateException("Unable to save password hash", exception);
        }
    }

    @Override
    public Optional<String> findPasswordHashByEmail(String email) {
        String sql = "SELECT password_hash FROM auth_credentials WHERE email = ?";

        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, normalizeEmail(email));
            try (ResultSet resultSet = statement.executeQuery()) {
                if (!resultSet.next()) {
                    return Optional.empty();
                }
                return Optional.of(resultSet.getString("password_hash"));
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("Unable to find password hash", exception);
        }
    }

    @Override
    public void close() {
        try {
            connection.close();
        } catch (SQLException exception) {
            throw new IllegalStateException("Unable to close SQLite auth repository", exception);
        }
    }

    private void initializeSchema() throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("""
                    CREATE TABLE IF NOT EXISTS auth_sessions (
                        session_id TEXT PRIMARY KEY,
                        user_id TEXT NOT NULL,
                        issued_at_epoch_ms INTEGER NOT NULL,
                        expires_at_epoch_ms INTEGER NOT NULL
                    )
                    """);
            statement.execute("""
                    CREATE TABLE IF NOT EXISTS auth_credentials (
                        email TEXT PRIMARY KEY,
                        password_hash TEXT NOT NULL
                    )
                    """);
        }
    }

    private String normalizeEmail(String email) {
        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException("Email is required");
        }
        return email.trim().toLowerCase();
    }
}