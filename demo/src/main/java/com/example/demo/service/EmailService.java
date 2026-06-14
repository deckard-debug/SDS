package com.example.demo.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {
    
    private final JavaMailSender mailSender;
    
    public boolean sendTwoFactorCode(String to, String code, String username) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(to);
            message.setSubject("🔐 Código de Verificación - Sistema de Seguridad");
            message.setText(String.format(
                "Hola %s,\n\n" +
                "Tu código de verificación es: %s\n\n" +
                "Este código expira en 5 minutos.\n\n" +
                "Si no solicitaste este código, ignora este mensaje.\n\n" +
                "Saludos,\nEquipo de Seguridad",
                username, code
            ));
            mailSender.send(message);
            log.info("✅ 2FA code sent to {}", to);
            return true;
        } catch (Exception e) {
            log.error("❌ Error sending email: {}", e.getMessage());
            return false;
        }
    }
    
    public boolean sendWelcomeEmail(String to, String username) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(to);
            message.setSubject("Bienvenido al Sistema de Seguridad");
            message.setText(String.format(
                "Hola %s,\n\n" +
                "Bienvenido al sistema. Tu cuenta ha sido creada exitosamente.\n\n" +
                "Saludos,\nEquipo de Seguridad",
                username
            ));
            mailSender.send(message);
            log.info("✅ Welcome email sent to {}", to);
            return true;
        } catch (Exception e) {
            log.error("❌ Error sending welcome email: {}", e.getMessage());
            return false;
        }
    }
}