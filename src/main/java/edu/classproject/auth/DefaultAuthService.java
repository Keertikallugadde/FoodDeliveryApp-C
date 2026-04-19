package edu.classproject.auth;

import edu.classproject.common.IdGenerator;
import edu.classproject.user.User;
import edu.classproject.user.UserService;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

public class DefaultAuthService implements AuthService {
    private final UserService userService;
    private final AuthRepository authRepository;
    private final Duration sessionTtl;
    private final Clock clock;

    public DefaultAuthService(UserService userService, AuthRepository authRepository) {
        this(userService, authRepository, Duration.ofHours(1), Clock.systemUTC());
    }

    public DefaultAuthService(UserService userService,
                              AuthRepository authRepository,
                              Duration sessionTtl,
                              Clock clock) {
        this.userService = userService;
        this.authRepository = authRepository;
        this.sessionTtl = sessionTtl;
        this.clock = clock;
    }

    @Override
    public AuthSession login(String email, String password) {
        if (password == null || password.isBlank()) {
            throw new IllegalArgumentException("Invalid credentials");
        }

        User user = resolveUserByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("Invalid credentials"));

        String normalizedEmail = user.email().trim().toLowerCase();
        String storedHash = authRepository.findPasswordHashByEmail(normalizedEmail).orElse(null);
        if (storedHash == null) {
            throw new IllegalArgumentException("Invalid credentials");
        }

        String providedHash = PasswordHasher.hash(normalizedEmail, password);
        if (!storedHash.equals(providedHash)) {
            throw new IllegalArgumentException("Invalid credentials");
        }

        Instant issuedAt = Instant.now(clock);
        AuthSession session = new AuthSession(
                IdGenerator.nextId("SES"),
                user.userId(),
                issuedAt,
                issuedAt.plus(sessionTtl)
        );
        authRepository.save(session);
        return session;
    }

    @Override
    public void logout(String sessionId) {
        if (sessionId == null || sessionId.isBlank()) {
            return;
        }
        authRepository.deleteBySessionId(sessionId);
    }

    @Override
    public boolean isSessionActive(String sessionId) {
        if (sessionId == null || sessionId.isBlank()) {
            return false;
        }

        Optional<AuthSession> session = authRepository.findBySessionId(sessionId);
        if (session.isEmpty()) {
            return false;
        }

        if (session.get().expiresAt().isAfter(Instant.now(clock))) {
            return true;
        }

        authRepository.deleteBySessionId(sessionId);
        return false;
    }

    private Optional<User> resolveUserByEmail(String email) {
        if (email == null || email.isBlank()) {
            return Optional.empty();
        }

        return userService.getAllUsers().stream()
                .filter(user -> user.email().equalsIgnoreCase(email))
                .findFirst();
    }
}