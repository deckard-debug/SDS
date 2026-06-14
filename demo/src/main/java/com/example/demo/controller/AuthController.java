// Archivo: src/main/java/com/example/demo/controller/AuthController.java
// Propósito: Endpoints de autenticación. Capa: Controller.

package com.example.demo.controller;

import com.example.demo.dto.AuthResponse;
import com.example.demo.dto.LoginRequest;
import com.example.demo.dto.RegisterRequest;
import com.example.demo.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(
            @Valid @RequestBody RegisterRequest request,
            HttpServletRequest httpRequest) {
        
        String ip = getClientIp(httpRequest);
        AuthResponse response = authService.register(request, ip);
        
        if (response.isSuccess()) {
            return ResponseEntity.ok(response);
        }
        return ResponseEntity.badRequest().body(response);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {
        
        String ip = getClientIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");
        
        AuthResponse response = authService.login(request, ip, userAgent);
        
        if (response.isSuccess()) {
            return ResponseEntity.ok(response);
        }
        if (response.isRequiresTwoFactor()) {
            return ResponseEntity.status(202).body(response);
        }
        return ResponseEntity.status(401).body(response);
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(
            @RequestHeader("Authorization") String authorization,
            HttpServletRequest httpRequest) {
        
                
        String token = authorization.substring(7);
        String ip = getClientIp(httpRequest);
        
        boolean success = authService.logout(token, ip);
        
        if (success) {
            return ResponseEntity.ok().body("{\"message\":\"Sesión cerrada exitosamente\"}");
        }
        return ResponseEntity.badRequest().body("{\"error\":\"Error al cerrar sesión\"}");
    }

    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    // Recuperación de contraseña - Obtener preguntas de seguridad
    @PostMapping("/get-security-questions")
    public ResponseEntity<?> getSecurityQuestions(@RequestBody Map<String, String> request) {
        String identifier = request.get("identifier");
        Map<String, Object> response = authService.getSecurityQuestions(identifier);
        return ResponseEntity.ok(response);
    }

    // Recuperación de contraseña - Enviar código
    @PostMapping("/send-recovery-code")
    public ResponseEntity<?> sendRecoveryCode(@RequestBody Map<String, String> request) {
        String identifier = request.get("identifier");
        String method = request.get("method");
        Map<String, Object> response = authService.sendRecoveryCode(identifier, method);
        return ResponseEntity.ok(response);
    }

    // Recuperación de contraseña - Restablecer
    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody Map<String, Object> request) {
        Map<String, Object> response = authService.resetPassword(request);
        return ResponseEntity.ok(response);
    }
}