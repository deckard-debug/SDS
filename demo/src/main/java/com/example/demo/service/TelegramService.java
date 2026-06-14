package com.example.demo.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
@Slf4j
public class TelegramService {
    
    @Value("${app.telegram.bot-token}")
    private String botToken;
    
    @Value("${app.telegram.admin-chat-id}")
    private String adminChatId;
    
    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();
    
    /**
     * Envía un mensaje a un chat de Telegram
     * @return true si se envió correctamente
     */
    public boolean sendMessage(String chatId, String message, String parseMode) {
        try {
            String url = "https://api.telegram.org/bot" + botToken + "/sendMessage";
            
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            
            String jsonBody = String.format(
                "{\"chat_id\":\"%s\",\"text\":%s,\"parse_mode\":\"%s\"}",
                chatId, jsonEscape(message), parseMode != null ? parseMode : ""
            );
            
            HttpEntity<String> entity = new HttpEntity<>(jsonBody, headers);
            ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.POST, entity, String.class);
            
            if (response.getStatusCode() == HttpStatus.OK) {
                JsonNode jsonResponse = objectMapper.readTree(response.getBody());
                if (jsonResponse.has("ok") && jsonResponse.get("ok").asBoolean()) {
                    log.info("Telegram message sent to {}", chatId);
                    return true;
                }
            }
            
            log.error("Telegram API error: {}", response.getBody());
            return false;
            
        } catch (Exception e) {
            log.error("Error sending Telegram message: {}", e.getMessage());
            return false;
        }
    }
    
    /**
     * Envía código 2FA por Telegram
     */
    public boolean sendTwoFactorCode(String chatId, String code, String username) {
        String message = String.format(
            "*CÓDIGO DE VERIFICACIÓN*\n\n" +
            "Hola *%s*, tu código de autenticación es:\n\n" +
            "`%s`\n\n" +
            "Este código expira en **5 minutos**.\n\n" +
            "Si no solicitaste este código, ignora este mensaje.",
            username, code
        );
        
        return sendMessage(chatId, message, "Markdown");
    }
    
    /**
     * Notifica nuevo inicio de sesión
     */
    public boolean notifyNewLogin(String chatId, String username, String ip, String userAgent) {
        String message = String.format(
            "*NUEVO INICIO DE SESIÓN*\n\n" +
            "**Usuario:** %s\n" +
            "**IP:** %s\n" +
            "**Dispositivo:** %s\n" +
            "**Fecha:** %s\n\n" +
            "Si no reconoces esta actividad, cambia tu contraseña inmediatamente.",
            username, ip, userAgent, java.time.LocalDateTime.now()
        );
        
        return sendMessage(chatId, message, "Markdown");
    }
    
    /**
     * Envía alerta de seguridad
     */
    public void sendSecurityAlert(String alertType, String details) {
        String message = String.format(
            "*ALERTA DE SEGURIDAD*\n\n" +
            "**Tipo:** %s\n" +
            "**Detalles:** %s\n" +
            "**Hora:** %s",
            alertType, details, java.time.LocalDateTime.now()
        );
        
        sendMessage(adminChatId, message, "Markdown");
    }
    
    private String jsonEscape(String s) {
        if (s == null) return "\"\"";
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }
}