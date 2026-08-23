package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.dto.auth.LoginRequest;
import io.github.raulperezmoreno71.threatintel.dto.auth.RegisterRequest;
import io.github.raulperezmoreno71.threatintel.entity.User;
import io.github.raulperezmoreno71.threatintel.exception.EmailAlreadyExistException;
import io.github.raulperezmoreno71.threatintel.exception.InvalidCredentialException;
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
}
