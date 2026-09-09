package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.dto.ChangePasswordRequest;
import io.github.raulperezmoreno71.threatintel.dto.auth.LoginRequest;
import io.github.raulperezmoreno71.threatintel.dto.auth.RegisterRequest;
import io.github.raulperezmoreno71.threatintel.entity.User;
import io.github.raulperezmoreno71.threatintel.exception.EmailAlreadyExistException;
import io.github.raulperezmoreno71.threatintel.exception.InvalidCredentialException;
import io.github.raulperezmoreno71.threatintel.exception.UserNotFoundException;
import io.github.raulperezmoreno71.threatintel.model.UserStatus;
import io.github.raulperezmoreno71.threatintel.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class UserServiceTest {

    private UserRepository userRepository;
    private PasswordEncoder passwordEncoder;
    private UserService userService;

    @BeforeEach
    void setUp() {
        userRepository = mock(UserRepository.class);
        passwordEncoder = mock(PasswordEncoder.class);

        userService = new UserService(userRepository, passwordEncoder);
    }

    @Test
    void shouldRegisterUserSuccessfully() {
        RegisterRequest request = new RegisterRequest(
                "raul@example.com",
                "prueba123"
        );

        when(userRepository.existsByEmail("raul@example.com")).thenReturn(false);
        when(passwordEncoder.encode("prueba123")).thenReturn("encoded-password");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        User result = userService.register(request);

        assertEquals("raul@example.com", result.getEmail());
        assertEquals("encoded-password", result.getPasswordHash());
        assertEquals(UserStatus.ACTIVE, result.getStatus());

        verify(userRepository).existsByEmail("raul@example.com");
        verify(passwordEncoder).encode("prueba123");
        verify(userRepository).save(any(User.class));
    }

    @Test
    void shouldThrowExceptionWhenEmailAlreadyExists() {
        RegisterRequest request = new RegisterRequest("raul@example.com", "prueba123");

        when(userRepository.existsByEmail("raul@example.com")).thenReturn(true);

        assertThrows(
                EmailAlreadyExistException.class,
                () -> userService.register(request)
        );

        verify(userRepository).existsByEmail("raul@example.com");
        verifyNoInteractions(passwordEncoder);
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void shouldLoginUserSuccessfully() {
        LoginRequest request = new LoginRequest("raul@example.com", "prueba123");
        User user = new User(
                "raul@example.com",
                "encoded-password",
                UserStatus.ACTIVE
        );

        when(userRepository.findByEmail("raul@example.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(request.getPassword(), user.getPasswordHash())).thenReturn(true);

        User saved = userService.login(request);

        assertEquals(saved.getEmail(), user.getEmail());
        assertEquals(saved.getStatus(), user.getStatus());
        assertSame(saved, user);

        verify(userRepository).findByEmail("raul@example.com");
        verify(passwordEncoder).matches(request.getPassword(), user.getPasswordHash());
    }

    @Test
    void shouldThrowInvalidCredentialExceptionWhenEmailDoesNotExist(){
        LoginRequest request = new LoginRequest("user@example.com", "prueba123");

        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.empty());

        InvalidCredentialException exception = assertThrows(
                InvalidCredentialException.class,
                () -> userService.login(request)
        );

        assertEquals("Invalid email or password", exception.getMessage());

        verify(userRepository).findByEmail("user@example.com");
        verifyNoInteractions(passwordEncoder);
    }

    @Test
    void shouldThrowInvalidCredentialExceptionWhenPasswordDoesNotMatch() {
        LoginRequest request = new LoginRequest("user@example.com", "prueba123");
        User user = new User(
                "user@example.com",
                "encoded-password",
                UserStatus.ACTIVE
        );

        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(request.getPassword(), user.getPasswordHash())).thenReturn(false);

        InvalidCredentialException exception = assertThrows(
                InvalidCredentialException.class,
                () -> userService.login(request)
        );

        assertEquals("Invalid email or password", exception.getMessage());

        verify(userRepository).findByEmail("user@example.com");
        verify(passwordEncoder).matches(request.getPassword(), user.getPasswordHash());
    }

    @Test
    void shouldReturnUserWhenEmailExists() {
        User user = new User(
                "user@example.com",
                "encoded-password",
                UserStatus.ACTIVE
        );

        when(userRepository.findByEmail("user@example.com"))
                .thenReturn(Optional.of(user));

        User result = userService.getByEmail("user@example.com");

        assertSame(user, result);

        verify(userRepository).findByEmail("user@example.com");
    }

    @Test
    void shouldThrowUserNotFoundExceptionWhenEmailDoesNotExist() {
        when(userRepository.findByEmail("missing@example.com"))
                .thenReturn(Optional.empty());

        UserNotFoundException exception = assertThrows(
                UserNotFoundException.class,
                () -> userService.getByEmail("missing@example.com")
        );

        assertEquals("User not found", exception.getMessage());

        verify(userRepository).findByEmail("missing@example.com");
    }

    @Test
    void shouldChangePasswordSuccessfully() {
        User user = new User(
                "user@example.com",
                "encoded-current-password",
                UserStatus.ACTIVE
        );
        ChangePasswordRequest request = new ChangePasswordRequest(
                "current-password",
                "new-password"
        );

        when(userRepository.findByEmail("user@example.com"))
                .thenReturn(Optional.of(user));
        when(passwordEncoder.matches("current-password", "encoded-current-password"))
                .thenReturn(true);
        when(passwordEncoder.matches("new-password", "encoded-current-password"))
                .thenReturn(false);
        when(passwordEncoder.encode("new-password"))
                .thenReturn("encoded-new-password");

        userService.changePassword("user@example.com", request);

        assertEquals("encoded-new-password", user.getPasswordHash());

        verify(userRepository).findByEmail("user@example.com");
        verify(passwordEncoder).matches("current-password", "encoded-current-password");
        verify(passwordEncoder).matches("new-password", "encoded-current-password");
        verify(passwordEncoder).encode("new-password");
        verify(userRepository).save(user);
    }

    @Test
    void shouldThrowUserNotFoundExceptionWhenChangingPasswordForUnknownUser() {
        ChangePasswordRequest request = new ChangePasswordRequest(
                "current-password",
                "new-password"
        );

        when(userRepository.findByEmail("missing@example.com"))
                .thenReturn(Optional.empty());

        UserNotFoundException exception = assertThrows(
                UserNotFoundException.class,
                () -> userService.changePassword("missing@example.com", request)
        );

        assertEquals("User not found", exception.getMessage());

        verify(userRepository).findByEmail("missing@example.com");
        verifyNoInteractions(passwordEncoder);
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void shouldRejectIncorrectCurrentPassword() {
        User user = new User(
                "user@example.com",
                "encoded-current-password",
                UserStatus.ACTIVE
        );
        ChangePasswordRequest request = new ChangePasswordRequest(
                "incorrect-password",
                "new-password"
        );

        when(userRepository.findByEmail("user@example.com"))
                .thenReturn(Optional.of(user));
        when(passwordEncoder.matches("incorrect-password", "encoded-current-password"))
                .thenReturn(false);

        InvalidCredentialException exception = assertThrows(
                InvalidCredentialException.class,
                () -> userService.changePassword("user@example.com", request)
        );

        assertEquals("Invalid password", exception.getMessage());
        assertEquals("encoded-current-password", user.getPasswordHash());

        verify(userRepository).findByEmail("user@example.com");
        verify(passwordEncoder).matches("incorrect-password", "encoded-current-password");
        verify(passwordEncoder, never()).encode(anyString());
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void shouldRejectNewPasswordEqualToCurrentPassword() {
        User user = new User(
                "user@example.com",
                "encoded-current-password",
                UserStatus.ACTIVE
        );
        ChangePasswordRequest request = new ChangePasswordRequest(
                "current-password",
                "current-password"
        );

        when(userRepository.findByEmail("user@example.com"))
                .thenReturn(Optional.of(user));
        when(passwordEncoder.matches("current-password", "encoded-current-password"))
                .thenReturn(true);

        InvalidCredentialException exception = assertThrows(
                InvalidCredentialException.class,
                () -> userService.changePassword("user@example.com", request)
        );

        assertEquals(
                "New password must be different from current password",
                exception.getMessage()
        );
        assertEquals("encoded-current-password", user.getPasswordHash());

        verify(userRepository).findByEmail("user@example.com");
        verify(passwordEncoder, times(2))
                .matches("current-password", "encoded-current-password");
        verify(passwordEncoder, never()).encode(anyString());
        verify(userRepository, never()).save(any(User.class));
    }
}
