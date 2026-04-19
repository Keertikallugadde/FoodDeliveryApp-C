package edu.classproject.auth;

import edu.classproject.user.DefaultUserService;
import edu.classproject.user.InMemoryUserRepository;
import edu.classproject.user.User;
import edu.classproject.user.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DefaultAuthServiceTest {
    private static final String EMAIL = "alex@example.edu";
    private static final String CREDENTIAL = "one-time-secret";

    private MutableClock clock;
    private AuthService authService;
    private InMemoryAuthRepository authRepository;

    @BeforeEach
    void setUp() {
        UserService userService = new DefaultUserService(new InMemoryUserRepository());
        User user = userService.registerCustomer("Alex", EMAIL);
        assertNotNull(user);

        authRepository = new InMemoryAuthRepository();
        authRepository.savePasswordHash(EMAIL, PasswordHasher.hash(EMAIL, CREDENTIAL));

        clock = new MutableClock(Instant.parse("2026-04-19T10:15:30Z"), ZoneId.of("UTC"));
        authService = new DefaultAuthService(
                userService,
            authRepository,
                Duration.ofMinutes(30),
                clock
        );
    }

    @Test
    void login_shouldCreateSession_whenCredentialsAreValid() {
        AuthSession session = authService.login(EMAIL, CREDENTIAL);

        assertNotNull(session);
        assertNotNull(session.sessionId());
        assertTrue(session.userId().startsWith("USR-"));
        assertTrue(authService.isSessionActive(session.sessionId()));
    }

    @Test
    void login_shouldReject_whenCredentialsAreInvalid() {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> authService.login(EMAIL, "wrong-password")
        );

        assertEquals("Invalid credentials", exception.getMessage());
    }

    @Test
    void login_shouldReject_whenUserDoesNotExist() {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> authService.login("missing@example.edu", CREDENTIAL)
        );

        assertEquals("Invalid credentials", exception.getMessage());
    }

    @Test
    void logout_shouldInvalidateSession() {
        AuthSession session = authService.login(EMAIL, CREDENTIAL);
        assertTrue(authService.isSessionActive(session.sessionId()));

        authService.logout(session.sessionId());

        assertFalse(authService.isSessionActive(session.sessionId()));
    }

    @Test
    void isSessionActive_shouldInvalidateExpiredSession() {
        AuthSession session = authService.login(EMAIL, CREDENTIAL);
        assertTrue(authService.isSessionActive(session.sessionId()));

        clock.advanceBy(Duration.ofMinutes(31));

        assertFalse(authService.isSessionActive(session.sessionId()));
        assertFalse(authService.isSessionActive(session.sessionId()));
    }

    private static final class MutableClock extends Clock {
        private Instant currentInstant;
        private final ZoneId zone;

        private MutableClock(Instant currentInstant, ZoneId zone) {
            this.currentInstant = currentInstant;
            this.zone = zone;
        }

        @Override
        public ZoneId getZone() {
            return zone;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return new MutableClock(currentInstant, zone);
        }

        @Override
        public Instant instant() {
            return currentInstant;
        }

        private void advanceBy(Duration duration) {
            currentInstant = currentInstant.plus(duration);
        }
    }
}