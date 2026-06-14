// Archivo: src/main/java/com/example/demo/service/AuthService.java
// Propósito: Lógica de negocio de autenticación. Capa: Service.

package com.example.demo.service;

import com.example.demo.dto.AuthResponse;
import com.example.demo.dto.LoginRequest;
import com.example.demo.dto.RegisterRequest;
import com.example.demo.model.*;
import com.example.demo.repository.*;
import com.example.demo.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final UserSessionRepository sessionRepository;
    private final SecurityLogRepository securityLogRepository;
    private final JwtTokenProvider tokenProvider;
    private final TelegramService telegramService;
    private final EmailService emailService;
    private final RateLimitService rateLimitService;

    @Value("${app.security.session-timeout}")
    private int sessionTimeoutMs;

    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    private final SecureRandom secureRandom = new SecureRandom();
    private final Map<String, String> twoFactorCodes = new HashMap<>();

    @Transactional
    public AuthResponse register(RegisterRequest request, String ip) {
        // Rate limiting
        if (!rateLimitService.checkRateLimit(ip, "register", 3, 60)) {
            return AuthResponse.builder()
                    .success(false)
                    .message("Demasiados intentos. Espera 1 minuto.")
                    .build();
        }

        // Validar existencia
        if (userRepository.existsByUsername(request.getUsername())) {
            return AuthResponse.builder()
                    .success(false)
                    .message("El usuario ya existe")
                    .build();
        }

        if (userRepository.existsByEmail(request.getEmail())) {
            return AuthResponse.builder()
                    .success(false)
                    .message("El email ya está registrado")
                    .build();
        }

        // Crear usuario
        String salt = generateSalt();
        String passwordHash = passwordEncoder.encode(request.getPassword() + salt);

        User user = new User();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPasswordHash(passwordHash);
        user.setSalt(salt);
        user.setTelegramChatId(request.getTelegramChatId());
        user.setTwoFactorEnabled(request.isTwoFactorEnabled());
        if (request.isTwoFactorEnabled()) {
            user.setTwoFactorMethod(User.TwoFactorMethod.valueOf(request.getTwoFactorMethod()));
        }

        user = userRepository.save(user);

        // Log
        SecurityLog log = SecurityLog.builder()
                .ip(ip)
                .eventType(SecurityLog.EventType.REGISTER_SUCCESS)
                .details("Usuario registrado: " + user.getUsername())
                .username(user.getUsername())
                .createdAt(LocalDateTime.now())
                .build();
        securityLogRepository.save(log);

        // Notificar por Telegram
        if (user.getTelegramChatId() != null && !user.getTelegramChatId().isEmpty()) {
            telegramService.sendMessage(user.getTelegramChatId(),
                    "Bienvenido " + user.getUsername() + "\n\nTu cuenta ha sido creada exitosamente.",
                    "Markdown");
        }

        return AuthResponse.builder()
                .success(true)
                .message("Usuario registrado exitosamente")
                .userId(user.getId())
                .build();
    }

    @Transactional
    public AuthResponse login(LoginRequest request, String ip, String userAgent) {
        // Rate limiting
        if (!rateLimitService.checkRateLimit(ip, "login", 5, 60)) {
            return AuthResponse.builder()
                    .success(false)
                    .message("Demasiados intentos. Intenta en 1 minuto.")
                    .build();
        }

        // Buscar usuario activo
        User user = userRepository.findByUsername(request.getUsername()).orElse(null);
        if (user == null) {
            logSecurityEvent(ip, SecurityLog.EventType.LOGIN_FAILED, "Usuario no encontrado", request.getUsername());
            return AuthResponse.builder()
                    .success(false)
                    .message("Credenciales inválidas")
                    .build();
        }

        // Verificar cuenta bloqueada
        if (user.isAccountLocked() && user.getLockExpiry() != null && user.getLockExpiry().isAfter(LocalDateTime.now())) {
            return AuthResponse.builder()
                    .success(false)
                    .message("Cuenta bloqueada hasta: " + user.getLockExpiry())
                    .build();
        }

        // Verificar contraseña
        String passwordWithSalt = request.getPassword() + user.getSalt();
        if (!passwordEncoder.matches(passwordWithSalt, user.getPasswordHash())) {
            user.setFailedAttempts(user.getFailedAttempts() + 1);
            if (user.getFailedAttempts() >= 5) {
                user.setAccountLocked(true);
                user.setLockExpiry(LocalDateTime.now().plusMinutes(30));
                logSecurityEvent(ip, SecurityLog.EventType.ACCOUNT_LOCKED, "Cuenta bloqueada por 5 intentos fallidos", user.getUsername());
            }
            userRepository.save(user);
            logSecurityEvent(ip, SecurityLog.EventType.LOGIN_FAILED, "Contraseña incorrecta", user.getUsername());
            return AuthResponse.builder()
                    .success(false)
                    .message("Credenciales inválidas")
                    .build();
        }

        // Resetear intentos fallidos
        user.setFailedAttempts(0);
        user.setAccountLocked(false);
        user.setLastLoginIp(ip);
        user.setLastLoginAt(LocalDateTime.now());
        userRepository.save(user);

        // Verificar 2FA
        if (user.isTwoFactorEnabled()) {
            if (request.getTwoFactorCode() == null || request.getTwoFactorCode().isEmpty()) {
                String code = generateTwoFactorCode();
                twoFactorCodes.put(user.getUsername(), code);

                if (user.getTwoFactorMethod() == User.TwoFactorMethod.TELEGRAM) {
                    telegramService.sendMessage(user.getTelegramChatId(),
                            "Tu código de verificación es: " + code, "Markdown");
                } else if (user.getTwoFactorMethod() == User.TwoFactorMethod.EMAIL) {
                    emailService.sendTwoFactorCode(user.getEmail(), code, user.getUsername());
                }

                return AuthResponse.builder()
                        .success(false)
                        .requiresTwoFactor(true)
                        .message("Se ha enviado un código de verificación")
                        .build();
            }

            String savedCode = twoFactorCodes.get(user.getUsername());
            if (!request.getTwoFactorCode().equals(savedCode)) {
                return AuthResponse.builder()
                        .success(false)
                        .message("Código 2FA inválido")
                        .build();
            }
            twoFactorCodes.remove(user.getUsername());
        }

        // Generar token JWT
        String token = tokenProvider.generateToken(user.getUsername(), ip, userAgent);

        // Guardar sesión
        UserSession session = new UserSession();
        session.setUser(user);
        session.setToken(token);
        session.setIpAddress(ip);
        session.setUserAgent(userAgent);
        session.setLastActivity(LocalDateTime.now());
        session.setExpiresAt(LocalDateTime.now().plusSeconds(sessionTimeoutMs / 1000));
        session.setCreatedAt(LocalDateTime.now());
        sessionRepository.save(session);

        // Invalidar otras sesiones si se requiere
        if (request.isSingleSession()) {
            sessionRepository.invalidateOtherSessions(user.getId(), token);
        }

        // Log
        logSecurityEvent(ip, SecurityLog.EventType.LOGIN_SUCCESS, "Login exitoso", user.getUsername());

        // Notificar nuevo login por Telegram
        if (user.getTelegramChatId() != null && !user.getTelegramChatId().isEmpty()) {
            telegramService.sendMessage(user.getTelegramChatId(),
                    "Nuevo inicio de sesión\nIP: " + ip + "\nDispositivo: " + userAgent,
                    "Markdown");
        }

        return AuthResponse.builder()
                .success(true)
                .token(token)
                .username(user.getUsername())
                .userId(user.getId())
                .expiresIn((long) sessionTimeoutMs)
                .build();
    }

    @Transactional
    public boolean logout(String token, String ip) {
        UserSession session = sessionRepository.findByTokenAndIsActiveTrue(token).orElse(null);
        if (session != null) {
            session.setActive(false);
            sessionRepository.save(session);
            logSecurityEvent(ip, SecurityLog.EventType.LOGOUT, "Cierre de sesión", session.getUser().getUsername());
            return true;
        }
        return false;
    }

    private String generateSalt() {
        byte[] salt = new byte[32];
        secureRandom.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    private String generateTwoFactorCode() {
        int code = 100000 + secureRandom.nextInt(900000);
        return String.valueOf(code);
    }

    private void logSecurityEvent(String ip, SecurityLog.EventType eventType, String details, String username) {
        SecurityLog log = SecurityLog.builder()
                .ip(ip)
                .eventType(eventType)
                .details(details)
                .username(username)
                .createdAt(LocalDateTime.now())
                .build();
        securityLogRepository.save(log);
    }


    // Obtener preguntas de seguridad de un usuario
    public Map<String, Object> getSecurityQuestions(String identifier) {
        Map<String, Object> response = new HashMap<>();
        
        User user = userRepository.findByUsername(identifier)
            .orElseGet(() -> userRepository.findByEmail(identifier).orElse(null));
        
        if (user == null) {
            response.put("success", false);
            response.put("message", "Usuario no encontrado");
            return response;
        }
        
        // Obtener preguntas de seguridad (necesitas crear la entidad SecurityQuestion)
        // Por ahora, simulamos preguntas predefinidas
        List<Map<String, String>> questions = new ArrayList<>();
        Map<String, String> q1 = new HashMap<>();
        q1.put("question", "¿Cuál es el nombre de tu primera mascota?");
        questions.add(q1);
        
        Map<String, String> q2 = new HashMap<>();
        q2.put("question", "¿En qué ciudad naciste?");
        questions.add(q2);
        
        response.put("success", true);
        response.put("questions", questions);
        return response;
    }

    // Enviar código de recuperación
    public Map<String, Object> sendRecoveryCode(String identifier, String method) {
        Map<String, Object> response = new HashMap<>();
        
        User user = userRepository.findByUsername(identifier)
            .orElseGet(() -> userRepository.findByEmail(identifier).orElse(null));
        
        if (user == null) {
            response.put("success", false);
            response.put("message", "Usuario no encontrado");
            return response;
        }
        
        String code = generateTwoFactorCode();
        recoveryCodes.put(user.getUsername() + "_recovery", code);
        
        if ("TELEGRAM".equals(method) && user.getTelegramChatId() != null) {
            telegramService.sendMessage(user.getTelegramChatId(), 
                "Tu código de recuperación es: " + code, "Markdown");
        } else if ("EMAIL".equals(method)) {
            emailService.sendTwoFactorCode(user.getEmail(), code, user.getUsername());
        } else {
            response.put("success", false);
            response.put("message", "Método de recuperación no disponible");
            return response;
        }
        
        response.put("success", true);
        response.put("message", "Código enviado");
        return response;
    }

    // Restablecer contraseña
    public Map<String, Object> resetPassword(Map<String, Object> request) {
        Map<String, Object> response = new HashMap<>();
        String identifier = (String) request.get("identifier");
        String newPassword = (String) request.get("newPassword");
        
        User user = userRepository.findByUsername(identifier)
            .orElseGet(() -> userRepository.findByEmail(identifier).orElse(null));
        
        if (user == null) {
            response.put("success", false);
            response.put("message", "Usuario no encontrado");
            return response;
        }
        
        // Verificar código o preguntas según el método
        if (request.containsKey("code")) {
            String code = (String) request.get("code");
            String storedCode = recoveryCodes.get(user.getUsername() + "_recovery");
            if (storedCode == null || !storedCode.equals(code)) {
                response.put("success", false);
                response.put("message", "Código inválido o expirado");
                return response;
            }
            recoveryCodes.remove(user.getUsername() + "_recovery");
        } else if (request.containsKey("answers")) {
            // Validar respuestas a preguntas de seguridad
            // Implementar según tus necesidades
        }
        
        // Actualizar contraseña
        String newSalt = generateSalt();
        String newPasswordHash = passwordEncoder.encode(newPassword + newSalt);
        user.setPasswordHash(newPasswordHash);
        user.setSalt(newSalt);
        userRepository.save(user);
        
        // Invalidar todas las sesiones activas
        sessionRepository.invalidateOtherSessions(user.getId(), null);
        
        response.put("success", true);
        response.put("message", "Contraseña restablecida exitosamente");
        return response;
    }

    // Mapa temporal para códigos de recuperación
    private final Map<String, String> recoveryCodes = new ConcurrentHashMap<>();
}